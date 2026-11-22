"""Bounded Kubernetes status overview; no general API proxy, shell or writes."""

from __future__ import annotations

import asyncio
import json
import os
import ssl
from collections import defaultdict
from pathlib import Path

import httpx2
from fastmcp import FastMCP

from ..authz import READ
from ..config import validate_k8s_api_url

_TOKEN_PATH = Path("/var/run/kule-k8s/token")
_CA_PATH = Path("/var/run/kule-k8s/ca.crt")
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024

_COLLECTIONS = {
    "nodes": "/api/v1/nodes?limit=500",
    "pods": "/api/v1/pods?limit=500",
    "deployments": "/apis/apps/v1/deployments?limit=500",
}


def _api_url() -> str | None:
    return validate_k8s_api_url(os.environ.get("KULE_K8S_API_URL", ""))


async def _list_items(
    client: httpx2.AsyncClient,
    base: str,
    path: str,
    headers: dict[str, str],
) -> list[dict]:
    try:
        # Reject all redirects before any second request could carry SA token.
        async with client.stream("GET", base + path, headers=headers) as response:
            if 300 <= response.status_code < 400:
                raise RuntimeError("Kubernetes API redirect refused")
            response.raise_for_status()
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise RuntimeError("Kubernetes response too large")
    except httpx2.HTTPError as exc:
        raise RuntimeError(f"Kubernetes status read failed ({type(exc).__name__})") from None
    try:
        result = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("Kubernetes returned invalid JSON") from None
    if not isinstance(result, dict) or not isinstance(result.get("items"), list):
        raise RuntimeError("Kubernetes returned invalid collection") from None
    if result.get("metadata", {}).get("continue"):
        raise RuntimeError("Kubernetes collection is paginated; refusing partial overview")
    return result["items"]


def summarize(nodes: list[dict], pods: list[dict], deployments: list[dict]) -> dict:
    """Project status only; never return raw Pod specs, logs or token fields."""
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


def register(mcp: FastMCP, *, timeout_seconds: float) -> None:
    base_url = _api_url()
    if base_url is None:
        return

    @mcp.tool(tags={READ}, annotations={"readOnlyHint": True, "openWorldHint": False})
    async def k8s_overview() -> dict:
        """Summarize Node readiness, namespace Pod counts and unavailable Deployments.

        No Secret, raw Pod spec, arbitrary API call, shell or write access.
        """
        token = _TOKEN_PATH.read_text().strip()
        if not token:
            raise RuntimeError("Kubernetes projected token is empty")
        context = ssl.create_default_context(cafile=str(_CA_PATH))
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        budget = max(0.1, min(8.0, timeout_seconds * 0.8))
        async with asyncio.timeout(budget):
            async with httpx2.AsyncClient(
                verify=context, timeout=5.0, trust_env=False, follow_redirects=False
            ) as client:
                responses = await asyncio.gather(
                    *(
                        _list_items(client, base_url, path, headers)
                        for path in _COLLECTIONS.values()
                    )
                )
        return summarize(*responses)
