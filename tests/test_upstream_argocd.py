"""Synthetic Argo CD observer contract: no live Argo credentials or network."""

import json
from pathlib import Path

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from operator_mcp.audit import AuditLog, verify
from operator_mcp.authz import Policy
from operator_mcp.middleware import OperatorMiddleware
from operator_mcp.tools import upstream_argocd as upstream


def test_fixed_https_endpoint_validation():
    assert upstream._url("https://argocd.example.test:443/") == "https://argocd.example.test:443"
    for value in (
        "",
        "http://argocd.example.test",
        "https://argocd.example.test/api",
        "https://user:pass@argocd.example.test",
        "https://argocd.example.test?url=x",
        "https://argocd.example.test#fragment",
        "https://argocd.example.test:bad",
        " https://argocd.example.test",
    ):
        with pytest.raises(RuntimeError, match="HTTPS origin"):
            upstream._url(value)


def test_registry_single_endpoint_scoped_and_no_secret_in_errors(tmp_path):
    registry = tmp_path / "token-registry.json"
    endpoint = "https://argocd.example.test"
    secret = "synthetic-secret-must-not-appear"
    registry.write_text(json.dumps([{"baseUrl": endpoint, "token": secret}]))
    registry.chmod(0o440)
    upstream._check_registry(registry, endpoint)
    registry.chmod(0o600)  # allow repeated writes as a non-root CI user
    for entries in (
        [{"baseUrl": "https://evil.example.test", "token": secret}],
        [{"baseUrl": endpoint, "token": ""}],
        [{"baseUrl": endpoint, "token": secret}, {"baseUrl": endpoint, "token": secret}],
        {"baseUrl": endpoint, "token": secret},
    ):
        registry.write_text(json.dumps(entries))
        with pytest.raises(RuntimeError, match="missing or invalid") as err:
            upstream._check_registry(registry, endpoint)
        assert secret not in str(err.value)
    registry.write_text(json.dumps([{"baseUrl": endpoint, "token": secret}]))
    registry.chmod(0o444)
    with pytest.raises(RuntimeError, match="missing or invalid"):
        upstream._check_registry(registry, endpoint)


def test_stdio_transport_pins_observer_and_never_uses_default_token(monkeypatch, tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps([{"baseUrl": "https://argocd.example.test", "token": "fake-token"}])
    )
    registry.chmod(0o440)
    monkeypatch.setattr(upstream, "_REGISTRY", registry)
    monkeypatch.setenv("KULE_ARGOCD_BASE_URL", "https://argocd.example.test")
    captured = {}

    class FakeTransport:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(upstream, "StdioTransport", FakeTransport)
    upstream._transport()
    assert captured["args"][-1] == "stdio"
    assert captured["env"]["MCP_READ_ONLY"] == "true"
    assert captured["env"]["ARGOCD_TOKEN_REGISTRY_PATH"] == str(registry)
    assert captured["env"]["ARGOCD_API_TOKEN"] == ""
    assert "fake-token" not in repr(captured)


async def test_argocd_proxy_exposes_only_reviewed_reads(tmp_path, monkeypatch):
    monkeypatch.setenv("KULE_ARGOCD_BASE_URL", "https://argocd.example.test")
    backend = FastMCP("synthetic-argocd")

    @backend.tool()
    def list_applications(argocdBaseUrl: str | None = None) -> str:
        return "apps-ok"

    @backend.tool()
    def get_application(applicationName: str) -> str:
        return applicationName

    @backend.tool()
    def get_application_resource_tree(applicationName: str) -> str:
        return f"tree:{applicationName}"

    @backend.tool()
    def get_application_events(applicationName: str) -> str:
        return f"events:{applicationName}"

    @backend.tool()
    def get_resources() -> str:
        return "SECRET_MANIFEST"

    @backend.tool()
    def get_application_workload_logs() -> str:
        return "UNBOUNDED_LOGS"

    @backend.tool()
    def sync_application() -> str:
        return "MUTATED"

    @backend.tool()
    def delete_application() -> str:
        return "DELETED"

    @backend.resource("private://argocd")
    def private_resource() -> str:
        return "SECRET"

    @backend.prompt()
    def private_prompt() -> str:
        return "SECRET"

    identity = {"claims": {"sub": "operator", "groups": ["ops"]}}
    audit_file = tmp_path / "audit.jsonl"
    gateway = FastMCP(
        "kule-argocd-synthetic",
        middleware=[
            OperatorMiddleware(
                policy=Policy(required_group="ops", exec_group="exec", exec_enabled=False),
                audit=AuditLog(audit_file),
                kill_switch=tmp_path / "DISABLED",
                timeout_seconds=5,
                max_output_bytes=4096,
                claims_getter=lambda: identity["claims"],
            )
        ],
    )
    upstream.mount(gateway, synthetic_backend=backend)
    async with Client(gateway) as client:
        assert {tool.name for tool in await client.list_tools()} == {
            "argocd_list_applications",
            "argocd_get_application",
            "argocd_get_application_resource_tree",
            "argocd_get_application_events",
        }
        assert await client.list_resources() == []
        assert await client.list_prompts() == []
        assert (await client.call_tool("argocd_list_applications", {})).data == "apps-ok"
        assert (
            await client.call_tool("argocd_get_application", {"applicationName": "staging"})
        ).data == "staging"
        assert (
            await client.call_tool(
                "argocd_get_application_resource_tree", {"applicationName": "staging"}
            )
        ).data == "tree:staging"
        assert (
            await client.call_tool("argocd_get_application_events", {"applicationName": "staging"})
        ).data == "events:staging"
        with pytest.raises(ToolError, match="not permitted"):
            await client.call_tool(
                "argocd_list_applications", {"argocdBaseUrl": "https://evil.example.test"}
            )
        for forbidden in (
            "argocd_sync_application",
            "argocd_delete_application",
            "argocd_get_resources",
            "argocd_get_application_workload_logs",
        ):
            with pytest.raises(ToolError, match="not authorized"):
                await client.call_tool(forbidden, {})

    identity["claims"] = {"sub": "outsider", "groups": []}
    async with Client(gateway) as client:
        assert await client.list_tools() == []
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("argocd_list_applications", {})

    assert verify(audit_file) == (True, 15)
    records = [json.loads(line) for line in audit_file.read_text().splitlines()]
    assert [record["event"] for record in records].count("result") == 4
    assert [record["event"] for record in records].count("denied") == 5
    assert [record["event"] for record in records].count("error") == 1


def test_locked_upstream_dependencies_and_integrity():
    pkg = json.loads(Path("contrib/argocd-mcp/package.json").read_text())
    lock = json.loads(Path("contrib/argocd-mcp/package-lock.json").read_text())
    assert pkg["dependencies"]["argocd-mcp"] == "0.9.0"
    assert lock["lockfileVersion"] == 3
    assert lock["packages"]["node_modules/argocd-mcp"]["version"] == "0.9.0"
    assert all(v.get("integrity") for k, v in lock["packages"].items() if k)
