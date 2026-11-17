"""Contract tests for the opt-in, read-only Kubernetes overview."""

from __future__ import annotations

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from helpers import OPERATOR, OUTSIDER

from operator_mcp.server import build_server
from operator_mcp.tools import kubernetes


def _fixture_data(path: str) -> list[dict]:
    if path.startswith("/api/v1/nodes"):
        return [
            {
                "metadata": {"name": "gurbet"},
                "status": {
                    "allocatable": {"cpu": "3500m", "memory": "20Gi"},
                    "conditions": [{"type": "Ready", "status": "True"}],
                },
            },
            {
                "metadata": {"name": "jelly"},
                "status": {
                    "allocatable": {"cpu": "2", "memory": "8Gi"},
                    "conditions": [{"type": "Ready", "status": "False"}],
                },
            },
        ]
    if path.startswith("/api/v1/pods"):
        return [
            {
                "metadata": {"name": "healthy", "namespace": "mcp-system"},
                "spec": {"containers": [{"env": [{"value": "super-secret-canary"}]}]},
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]},
            },
            {
                "metadata": {"name": "waiting", "namespace": "staging"},
                "status": {"phase": "Pending", "conditions": []},
            },
        ]
    if path.startswith("/apis/apps/v1/deployments"):
        return [
            {
                "metadata": {"name": "operator-mcp", "namespace": "mcp-system"},
                "spec": {"replicas": 1},
                "status": {"availableReplicas": 1},
            },
            {
                "metadata": {"name": "unhealthy", "namespace": "staging"},
                "spec": {"replicas": 2},
                "status": {"availableReplicas": 1},
            },
        ]
    raise AssertionError("Unexpected Kubernetes API path")


def test_summary_has_no_secrets_specs_or_logs():
    result = kubernetes.summarize(
        _fixture_data("/api/v1/nodes"),
        _fixture_data("/api/v1/pods"),
        _fixture_data("/apis/apps/v1/deployments"),
    )
    assert result["pod_total"] == 2
    assert [(n["name"], n["ready"]) for n in result["nodes"]] == [
        ("gurbet", True),
        ("jelly", False),
    ]
    assert result["namespace_pods"] == [
        {
            "namespace": "mcp-system",
            "total": 1,
            "running": 1,
            "pending": 0,
            "failed": 0,
            "not_ready": 0,
        },
        {
            "namespace": "staging",
            "total": 1,
            "running": 0,
            "pending": 1,
            "failed": 0,
            "not_ready": 1,
        },
    ]
    assert result["unavailable_deployments"] == [
        {"namespace": "staging", "name": "unhealthy", "desired": 2, "available": 1}
    ]
    assert "super-secret-canary" not in str(result)
    assert "env" not in str(result)
    assert "containers" not in str(result)


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.1.248:6443",
        "https://user:password@localhost:6443",
        "https://localhost:6443/api",
        "https://localhost:6443?watch=true",
        "https://localhost:6443/#fragment",
    ],
)
def test_explicit_api_url_is_restricted(monkeypatch, url):
    monkeypatch.setenv("KULE_K8S_API_URL", url)
    with pytest.raises(ValueError):
        kubernetes._api_url()


def test_no_api_configuration_means_no_k8s_tools(make_cfg, claims, monkeypatch):
    monkeypatch.delenv("KULE_K8S_API_URL", raising=False)
    mcp = build_server(make_cfg(), claims_getter=claims)
    assert mcp is not None


async def test_k8s_overview_operator_only_with_audit(make_cfg, claims, monkeypatch):
    monkeypatch.setenv("KULE_K8S_API_URL", "https://10.0.1.248:6443")
    requests = []

    def fake_api_get(base: str, path: str) -> list[dict]:
        assert base == "https://10.0.1.248:6443"
        assert path in kubernetes._COLLECTIONS.values()
        requests.append(path)
        return _fixture_data(path)

    monkeypatch.setattr(kubernetes, "_list_items", fake_api_get)
    cfg = make_cfg()
    mcp = build_server(cfg, claims_getter=claims)
    claims.value = OPERATOR
    async with Client(mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
        assert set(tools) == {"whoami", "note_write", "k8s_overview"}
        assert tools["k8s_overview"].annotations.read_only_hint
        result = await client.call_tool("k8s_overview", {})
        assert result.data["pod_total"] == 2
        assert len(requests) == 3
    claims.value = OUTSIDER
    async with Client(mcp) as client:
        assert await client.list_tools() == []
        with pytest.raises(ToolError):
            await client.call_tool("k8s_overview", {})
    assert not requests[3:]
    assert cfg.audit.path.exists()
    assert "k8s_overview" in cfg.audit.path.read_text()
