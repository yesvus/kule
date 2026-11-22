"""Source-only contract for an opt-in official Kubernetes MCP backend."""

import json
import tomllib

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from kule.audit import AuditLog, verify
from kule.authz import Policy
from kule.middleware import OperatorMiddleware
from kule.tools import upstream_kubernetes as upstream


def test_projected_token_is_referenced_never_copied(monkeypatch, tmp_path):
    token = tmp_path / "token"
    token.write_text("synthetic-secret-not-for-kubeconfig")
    ca = tmp_path / "ca.crt"
    ca.write_text("synthetic-ca")
    monkeypatch.setattr(upstream, "_TOKEN", token)
    monkeypatch.setattr(upstream, "_CA", ca)
    monkeypatch.setattr(upstream, "_KUBECONFIG", tmp_path / "kubeconfig")
    monkeypatch.setenv("KULE_K8S_API_URL", "https://127.0.0.1:6443")
    path = upstream._write_kubeconfig()
    data = json.loads(path.read_text())
    assert data["clusters"][0]["cluster"]["server"] == "https://127.0.0.1:6443"
    assert data["users"][0]["user"]["tokenFile"] == str(token)
    assert "synthetic-secret-not-for-kubeconfig" not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600


def test_upstream_config_is_small_read_only_and_does_not_enable_exec():
    path = "contrib/kubernetes-upstream.toml"
    with open(path, "rb") as source:
        config = tomllib.load(source)
    assert config["read_only"] is True
    assert config["kubeconfig"] == "/tmp/kule-upstream-kubeconfig.json"
    assert config["toolsets"] == ["core"]
    assert config["enabled_tools"] == ["pods_list", "events_list", "pods_log"]
    assert "pods_exec" not in config["enabled_tools"]
    assert any(item["kind"] == "Secret" for item in config["denied_resources"])


async def test_upstream_mount_blocks_untagged_and_nontool_components(tmp_path):
    backend = FastMCP("synthetic-upstream")

    @backend.tool()
    def pods_list() -> str:
        return "pods-ok"

    @backend.tool()
    def pods_exec() -> str:
        return "never"

    @backend.resource("private://sample")
    def hidden_resource() -> str:
        return "hidden"

    @backend.prompt()
    def hidden_prompt() -> str:
        return "hidden"

    caller = {"claims": {"sub": "operator", "groups": ["ops"]}}
    audit = tmp_path / "audit.jsonl"
    gateway = FastMCP(
        "kule-allowlist",
        middleware=[
            OperatorMiddleware(
                policy=Policy(required_group="ops", exec_group="exec", exec_enabled=False),
                audit=AuditLog(audit),
                kill_switch=tmp_path / "DISABLED",
                timeout_seconds=5,
                max_output_bytes=4096,
                claims_getter=lambda: caller["claims"],
            )
        ],
    )
    upstream.mount(gateway, synthetic_backend=backend)

    async with Client(gateway) as client:
        assert {t.name for t in await client.list_tools()} == {"k8s_pods_list"}
        assert await client.list_resources() == []
        assert await client.list_prompts() == []
        assert (await client.call_tool("k8s_pods_list", {})).data == "pods-ok"
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("k8s_pods_exec", {})

    caller["claims"] = {"sub": "outsider", "groups": []}
    async with Client(gateway) as client:
        assert await client.list_tools() == []
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("k8s_pods_list", {})

    assert verify(audit) == (True, 4)
