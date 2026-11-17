"""Small allowlisted Kubernetes diagnostics. No shell, API proxy, or writes."""

from __future__ import annotations

import asyncio
import os
import re
import ssl
from typing import Annotated
from urllib.parse import urlencode

import httpx2
from fastmcp import FastMCP
from pydantic import Field

from ..authz import READ
from ..redact import redact_text
from .kubernetes import _CA_PATH, _TOKEN_PATH, _api_url, _list_items

# Kubernetes DNS-label names only. Reject slash, query, percent and escapes.
_NAME = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
_LOG_MAX_BYTES = 4096


def _name(value: str, label: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise ValueError(f"{label} must be a Kubernetes DNS-label name (1-63 chars)")
    return value


def _log_namespaces() -> frozenset[str]:
    raw = os.environ.get("KULE_K8S_LOG_NAMESPACES", "")
    items = [x.strip() for x in raw.split(",") if x.strip()]
    if len(items) != len(set(items)):
        raise ValueError("KULE_K8S_LOG_NAMESPACES has duplicate entries")
    for ns in items:
        _name(ns, "log namespace")
    return frozenset(items)


def _headers() -> dict[str, str]:
    token = _TOKEN_PATH.read_text().strip()
    if not token:
        raise RuntimeError("Kubernetes projected token is empty")
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _client() -> httpx2.AsyncClient:
    ctx = ssl.create_default_context(cafile=str(_CA_PATH))
    return httpx2.AsyncClient(verify=ctx, timeout=5.0, trust_env=False, follow_redirects=False)


async def _collection(base: str, path: str, timeout_seconds: float) -> list[dict]:
    async with asyncio.timeout(min(8.0, timeout_seconds * 0.8)):
        async with _client() as client:
            return await _list_items(client, base, path, _headers())


async def _log_text(
    client: httpx2.AsyncClient, base: str, path: str, headers: dict[str, str]
) -> str:
    try:
        async with client.stream("GET", base + path, headers=headers) as response:
            if 300 <= response.status_code < 400:
                raise RuntimeError("Kubernetes API redirect refused")
            response.raise_for_status()
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > _LOG_MAX_BYTES:
                    raise RuntimeError("Kubernetes logs exceed bounded response")
    except httpx2.HTTPError as exc:
        # Never propagate response contents, token or URL.
        raise RuntimeError(f"Kubernetes log read failed ({type(exc).__name__})") from None
    return redact_text(body.decode("utf-8", errors="replace"))


def _pod_summary(pod: dict) -> dict:
    stat = pod.get("status", {})
    cs = stat.get("containerStatuses", [])
    ready = any(
        c.get("type") == "Ready" and c.get("status") == "True" for c in stat.get("conditions", [])
    )
    waiting = sorted(
        {
            c.get("state", {}).get("waiting", {}).get("reason", "")
            for c in cs
            if c.get("state", {}).get("waiting")
        }
        - {""}
    )
    return {
        "name": pod.get("metadata", {}).get("name", ""),
        "phase": stat.get("phase", "Unknown"),
        "ready": ready,
        "node": pod.get("spec", {}).get("nodeName", ""),
        "restarts": sum(c.get("restartCount", 0) for c in cs),
        "waiting_reasons": waiting,
    }


def _deployment_summary(dep: dict) -> dict:
    spec, status = dep.get("spec", {}), dep.get("status", {})
    return {
        "name": dep.get("metadata", {}).get("name", ""),
        "desired": spec.get("replicas", 1),
        "ready": status.get("readyReplicas", 0),
        "available": status.get("availableReplicas", 0),
        "updated": status.get("updatedReplicas", 0),
        "unavailable": status.get("unavailableReplicas", 0),
    }


def _event_summary(event: dict) -> dict:
    obj = event.get("involvedObject", {})
    return {
        "type": event.get("type", ""),
        "reason": event.get("reason", ""),
        "object_kind": obj.get("kind", ""),
        "object_name": obj.get("name", ""),
        "count": event.get("count", 1),
        "last_seen": (
            event.get("lastTimestamp")
            or event.get("eventTime")
            or event.get("metadata", {}).get("creationTimestamp", "")
        ),
        "message": redact_text(event.get("message", "")[:350]),
    }


def register(mcp: FastMCP, *, timeout_seconds: float) -> None:
    base = _api_url()
    if base is None:
        return
    allowed_logs = _log_namespaces()

    @mcp.tool(tags={READ}, annotations={"readOnlyHint": True, "openWorldHint": False})
    async def k8s_pods(
        namespace: Annotated[str, Field(description="Kubernetes namespace DNS label")],
    ) -> dict:
        """List Pod readiness, restart counts, waiting reasons and node in one namespace."""
        ns = _name(namespace, "namespace")
        items = await _collection(base, f"/api/v1/namespaces/{ns}/pods?limit=500", timeout_seconds)
        result = sorted((_pod_summary(p) for p in items), key=lambda p: p["name"])
        return {
            "namespace": ns,
            "total": len(items),
            "pods": result[:100],
            "truncated": len(result) > 100,
        }

    @mcp.tool(tags={READ}, annotations={"readOnlyHint": True, "openWorldHint": False})
    async def k8s_deployments(
        namespace: Annotated[str, Field(description="Kubernetes namespace DNS label")],
    ) -> dict:
        """List desired/ready/available Deployment replicas in a namespace."""
        ns = _name(namespace, "namespace")
        path = f"/apis/apps/v1/namespaces/{ns}/deployments?limit=500"
        items = await _collection(base, path, timeout_seconds)
        result = sorted((_deployment_summary(p) for p in items), key=lambda p: p["name"])
        return {
            "namespace": ns,
            "total": len(items),
            "deployments": result[:100],
            "truncated": len(result) > 100,
        }

    @mcp.tool(tags={READ}, annotations={"readOnlyHint": True, "openWorldHint": False})
    async def k8s_events(
        namespace: Annotated[str, Field(description="Kubernetes namespace DNS label")],
    ) -> dict:
        """Show recent Kubernetes Events (types, reasons, bounded redacted messages)."""
        ns = _name(namespace, "namespace")
        items = await _collection(
            base, f"/api/v1/namespaces/{ns}/events?limit=500", timeout_seconds
        )
        result = sorted(
            (_event_summary(e) for e in items),
            key=lambda e: e["last_seen"],
            reverse=True,
        )
        return {
            "namespace": ns,
            "total": len(items),
            "events": result[:40],
            "truncated": len(items) > 40,
        }

    if not allowed_logs:
        return

    @mcp.tool(tags={READ}, annotations={"readOnlyHint": True, "openWorldHint": False})
    async def k8s_pod_logs(
        namespace: Annotated[str, Field(description="Approved staging namespace")],
        pod: Annotated[str, Field(description="Exact Pod name")],
        tail_lines: Annotated[int, Field(ge=1, le=50)] = 40,
        container: Annotated[str | None, Field(description="Optional exact container name")] = None,
    ) -> dict:
        """Read at most 4KiB / 50 lines of redacted logs from allowlisted staging namespaces.

        Logs may contain sensitive application data despite best-effort redaction.
        """
        ns = _name(namespace, "namespace")
        if ns not in allowed_logs:
            raise ValueError("Kubernetes Pod log reads not enabled in this namespace")
        pod = _name(pod, "pod")
        if container is not None:
            container = _name(container, "container")
        if not 1 <= tail_lines <= 50:
            raise ValueError("tail_lines must be between 1 and 50")
        params = {
            "tailLines": str(tail_lines),
            "limitBytes": str(_LOG_MAX_BYTES),
            "timestamps": "true",
        }
        if container:
            params["container"] = container
        path = f"/api/v1/namespaces/{ns}/pods/{pod}/log?" + urlencode(params)
        async with asyncio.timeout(min(8.0, timeout_seconds * 0.8)):
            async with _client() as client:
                body = await _log_text(client, base, path, _headers())
        return {
            "namespace": ns,
            "pod": pod,
            "container": container,
            "tail_lines": tail_lines,
            "logs": body,
        }
