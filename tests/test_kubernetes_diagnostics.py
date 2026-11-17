"""Diagnostics tool contracts: fixed paths, bounded output, operator authorization."""

from __future__ import annotations

import httpx2
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from helpers import OPERATOR, OUTSIDER

from operator_mcp.server import build_server
from operator_mcp.tools import kubernetes_diagnostics as d


def test_path_names_fail_closed():
    for name in ("../x", "a/b", "x?watch=true", "x%2fy", "", ".x", "UPPER", "a" * 65):
        with pytest.raises(ValueError):
            d._name(name, "namespace")
    assert d._name("birted-staging", "namespace") == "birted-staging"


def test_status_projects_only_safe_fields():
    p = {
        "metadata": {"name": "web-abc"},
        "spec": {"nodeName": "gurbet", "containers": [{"env": [{"value": "secret-value"}]}]},
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "False"}],
            "containerStatuses": [
                {"restartCount": 3, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}
            ],
        },
    }
    result = d._pod_summary(p)
    assert result == {
        "name": "web-abc",
        "phase": "Running",
        "ready": False,
        "node": "gurbet",
        "restarts": 3,
        "waiting_reasons": ["CrashLoopBackOff"],
    }
    assert "secret-value" not in str(result)


def test_event_redacts_secret_fields():
    event = {
        "type": "Warning",
        "reason": "ProbeFailed",
        "message": "request failed: api_key=synthetic-event-token",
        "involvedObject": {"kind": "Pod", "name": "test"},
    }
    text = str(d._event_summary(event))
    assert "synthetic-event-token" not in text
    assert "[REDACTED]" in text


@pytest.mark.parametrize("invalid", ["x,x", "good,../oops", "UPPER"])
def test_log_scope_invalid(monkeypatch, invalid):
    monkeypatch.setenv("KULE_K8S_LOG_NAMESPACES", invalid)
    with pytest.raises(ValueError):
        d._log_namespaces()


async def test_allowed_operator_sees_tools_and_namespaced_paths(make_cfg, claims, monkeypatch):
    monkeypatch.setenv("KULE_K8S_API_URL", "https://10.0.1.248:6443")
    monkeypatch.setenv("KULE_K8S_LOG_NAMESPACES", "birted-staging")
    calls = []

    async def fake_collection(base, path, timeout_seconds):
        assert base == "https://10.0.1.248:6443"
        calls.append(path)
        if path.endswith("/pods?limit=500"):
            return [
                {
                    "metadata": {"name": "web"},
                    "status": {
                        "phase": "Running",
                        "conditions": [{"type": "Ready", "status": "True"}],
                    },
                }
            ]
        if path.endswith("/deployments?limit=500"):
            return [
                {
                    "metadata": {"name": "store"},
                    "spec": {"replicas": 2},
                    "status": {"readyReplicas": 1},
                }
            ]
        if path.endswith("/events?limit=500"):
            return [{"metadata": {"creationTimestamp": "2026-11-17T15:00:00Z"}, "message": "ready"}]
        raise AssertionError(path)

    async def fake_log_text(client, base, path, headers):
        calls.append(path)
        return "safe logs"

    monkeypatch.setattr(d, "_collection", fake_collection)
    monkeypatch.setattr(d, "_log_text", fake_log_text)
    monkeypatch.setattr(d, "_headers", lambda: {"Authorization": "Bearer synthetic"})
    monkeypatch.setattr(
        d,
        "_client",
        lambda: httpx2.AsyncClient(
            transport=httpx2.MockTransport(lambda req: httpx2.Response(200))
        ),
    )
    cfg = make_cfg()
    mcp = build_server(cfg, claims_getter=claims)
    claims.value = OPERATOR
    async with Client(mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
        assert set(tools) == {
            "whoami",
            "note_write",
            "k8s_overview",
            "k8s_pods",
            "k8s_deployments",
            "k8s_events",
            "k8s_pod_logs",
        }
        assert all(t.annotations.read_only_hint for n, t in tools.items() if n.startswith("k8s_"))
        pod = await client.call_tool("k8s_pods", {"namespace": "birted-staging"})
        assert pod.data["pods"][0]["name"] == "web"
        dep = await client.call_tool("k8s_deployments", {"namespace": "birted-staging"})
        assert dep.data["deployments"][0]["ready"] == 1
        ev = await client.call_tool("k8s_events", {"namespace": "birted-staging"})
        assert ev.data["total"] == 1
        log = await client.call_tool("k8s_pod_logs", {"namespace": "birted-staging", "pod": "web"})
        assert log.data["logs"] == "safe logs"
        assert len(calls) == 4
        assert all("birted-staging" in p for p in calls)
        with pytest.raises(ToolError):
            await client.call_tool("k8s_pod_logs", {"namespace": "openbao", "pod": "vault-0"})
        with pytest.raises(ToolError):
            await client.call_tool("k8s_pods", {"namespace": "../danger"})
    claims.value = OUTSIDER
    async with Client(mcp) as client:
        assert await client.list_tools() == []
        with pytest.raises(ToolError):
            await client.call_tool("k8s_events", {"namespace": "birted-staging"})
    assert len(calls) == 4


async def test_no_log_scope_does_not_advertise_tool(make_cfg, claims, monkeypatch):
    monkeypatch.setenv("KULE_K8S_API_URL", "https://10.0.1.248:6443")
    monkeypatch.delenv("KULE_K8S_LOG_NAMESPACES", raising=False)
    claims.value = OPERATOR
    async with Client(build_server(make_cfg(), claims_getter=claims)) as client:
        names = {t.name for t in await client.list_tools()}
        assert {"k8s_pods", "k8s_events", "k8s_deployments"} <= names
        assert "k8s_pod_logs" not in names


async def test_log_redirect_denied_before_follow():
    visited = []

    def handler(request):
        visited.append(request.url.host)
        return httpx2.Response(302, headers={"Location": "https://attacker.invalid"})

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler), follow_redirects=False
    ) as client:
        with pytest.raises(RuntimeError, match="redirect refused"):
            await d._log_text(
                client,
                "https://10.0.1.248:6443",
                "/api/v1/namespaces/birted-staging/pods/web/log?tailLines=20",
                {"Authorization": "Bearer synthetic"},
            )
    assert visited == ["10.0.1.248"]
