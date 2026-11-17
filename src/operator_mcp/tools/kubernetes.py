"""Bounded, read-only Kubernetes health snapshot for an explicitly configured API.

No kubectl, shell, dynamic resource paths, patch/delete/watch, pod logs,
Secrets, or credential data are exposed through this MCP tool.
"""

from __future__ import annotations

import json
import os
import ssl
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from fastmcp import FastMCP

from ..authz import READ

_TOKEN_PATH = Path("/var/run/kule-k8s/token")
_CA_PATH = Path("/var/run/kule-k8s/ca.crt")
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024

# Fixed collection routes. Do not add a user-supplied Kubernetes URL or path.
_COLLECTIONS = {
    "nodes": "/api/v1/nodes?limit=500",
    "pods": "/api/v1/pods?limit=500",
    "deployments": "/apis/apps/v1/deployments?limit=500",
}


def _api_url() -> str | None:
    base = os.environ.get("KULE_K8S_API_URL", "").rstrip("/")
    if not base:
        return None
    parsed = urlsplit(base)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("KULE_K8S_API_URL must be an HTTPS origin without a path")
    return base


def _list_items(base: str, path: str) -> list[dict]:
    # Trust only the explicitly mounted Kubernetes CA, never -k/insecure TLS.
    # Disable ambient HTTPS_PROXY to prevent routing a bearer token elsewhere.
    context = ssl.create_default_context(cafile=str(_CA_PATH))
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    token = _TOKEN_PATH.read_text().strip()
    if not token:
        raise RuntimeError("Kubernetes projected token is empty")
    # _api_url enforces HTTPS-origin-only and path comes from _COLLECTIONS.
    request = Request(  # noqa: S310
        base + path,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=6) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except Exception as exc:
        # No Authorization header, bearer token or complete URL in audit errors.
        raise RuntimeError(f"Kubernetes status read failed ({type(exc).__name__})") from None
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise RuntimeError("Kubernetes response too large for safe bounded overview")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("Kubernetes returned invalid JSON") from None
    if not isinstance(result, dict) or not isinstance(result.get("items"), list):
        raise RuntimeError("Kubernetes returned an invalid collection")
    if result.get("metadata", {}).get("continue"):
        raise RuntimeError("Kubernetes collection is paginated; refusing partial overview")
    return result["items"]


def summarize(nodes: list[dict], pods: list[dict], deployments: list[dict]) -> dict:
    """Project status only; never return raw Pod specs, env, Secret refs or tokens."""
    node_status = []
    for node in nodes:
        status = node.get("status", {})
        ready = next(
            (
                c.get("status") == "True"
                for c in status.get("conditions", [])
                if c.get("type") == "Ready"
            ),
            False,
        )
        node_status.append(
            {
                "name": node.get("metadata", {}).get("name", ""),
                "ready": ready,
                "allocatable_cpu": status.get("allocatable", {}).get("cpu"),
                "allocatable_memory": status.get("allocatable", {}).get("memory"),
            }
        )

    namespaces: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "running": 0, "pending": 0, "failed": 0, "not_ready": 0}
    )
    for pod in pods:
        ns = pod.get("metadata", {}).get("namespace", "default")
        phase = pod.get("status", {}).get("phase", "Unknown")
        record = namespaces[ns]
        record["total"] += 1
        if phase == "Running":
            record["running"] += 1
        if phase == "Pending":
            record["pending"] += 1
        if phase == "Failed":
            record["failed"] += 1
        if phase not in ("Succeeded", "Failed"):
            conditions = pod.get("status", {}).get("conditions", [])
            if not any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions):
                record["not_ready"] += 1

    unhealthy_deployments = []
    for deployment in deployments:
        desired = deployment.get("spec", {}).get("replicas", 1)
        available = deployment.get("status", {}).get("availableReplicas", 0)
        if available < desired:
            unhealthy_deployments.append(
                {
                    "namespace": deployment.get("metadata", {}).get("namespace", ""),
                    "name": deployment.get("metadata", {}).get("name", ""),
                    "desired": desired,
                    "available": available,
                }
            )
    return {
        "nodes": sorted(node_status, key=lambda n: n["name"]),
        "pod_total": len(pods),
        "namespace_pods": [
            {"namespace": ns, **record} for ns, record in sorted(namespaces.items())
        ],
        "unavailable_deployments": sorted(
            unhealthy_deployments, key=lambda d: (d["namespace"], d["name"])
        )[:30],
        "unavailable_deployments_truncated": len(unhealthy_deployments) > 30,
    }


def register(mcp: FastMCP) -> None:
    base_url = _api_url()
    if base_url is None:
        # Feature off by default; not advertised to users until source-controlled
        # projected credentials + least-privilege RBAC + egress are deployed.
        return

    @mcp.tool(tags={READ}, annotations={"readOnlyHint": True, "openWorldHint": False})
    def k8s_overview() -> dict:
        """Summarize cluster node readiness, per-namespace Pod counts, and unhealthy Deployments.

        Read-only. Never returns Pod specs, secrets, logs or shell access.
        """
        return summarize(
            _list_items(base_url, _COLLECTIONS["nodes"]),
            _list_items(base_url, _COLLECTIONS["pods"]),
            _list_items(base_url, _COLLECTIONS["deployments"]),
        )
