"""Opt-in Argo CD MCP observer behind Kule's existing OAuth and audit gateway.

Use the maintained Argo Project Labs stdio server with a single pinned Argo
endpoint and an OpenBao/ESO-mounted, read-only Argo API token registry. Never
expose upstream HTTP, prompts, resources, sync or generic resource manifests.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from fastmcp import FastMCP
from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy
from fastmcp.server.transforms import ToolTransform
from fastmcp.server.transforms.tool_transform import ToolTransformConfig

_NODE = "/usr/local/bin/node"
_ENTRYPOINT = "/opt/argocd-mcp/node_modules/argocd-mcp/dist/index.js"
_REGISTRY = Path("/var/run/kule-argocd/token-registry.json")

# Additional upstream tools are invisible and denied, even after upgrades.
# In particular: no raw manifests, Secret reads, workload logs or write tools.
_READ_TOOLS = (
    "list_applications",
    "get_application",
    "get_application_resource_tree",
    "get_application_events",
)


def _url(raw: str) -> str:
    """Require one fixed HTTPS origin; no userinfo, path or redirects."""
    if not raw or raw != raw.strip() or "?" in raw or "#" in raw:
        raise RuntimeError("KULE_ARGOCD_BASE_URL must be an HTTPS origin")
    base = raw.rstrip("/")
    try:
        parsed = urlsplit(base)
        port = parsed.port
    except ValueError:
        raise RuntimeError("KULE_ARGOCD_BASE_URL must be an HTTPS origin") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise RuntimeError("KULE_ARGOCD_BASE_URL must be an HTTPS origin")
    return base


def _check_registry(path: Path, expected_url: str) -> None:
    """Fail closed if the secret volume can target any other Argo endpoint.

    Do not include secret file contents, parse errors or tokens in exceptions.
    """
    try:
        if not path.is_file() or path.stat().st_mode & 0o007:
            raise ValueError("missing or world-accessible registry")
        entries = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(entries, list) or len(entries) != 1:
            raise ValueError("expected one Argo instance")
        entry = entries[0]
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("baseUrl"), str)
            or _url(entry["baseUrl"]) != expected_url
            or not isinstance(entry.get("token"), str)
            or not entry["token"].strip()
        ):
            raise ValueError("unapproved Argo instance or empty token")
    except (OSError, ValueError, TypeError, UnicodeError):
        raise RuntimeError("Kule Argo CD token registry is missing or invalid") from None


def _transport() -> StdioTransport:
    """Credentials belong to the upstream observer only, not tool arguments."""
    endpoint = _url(os.environ.get("KULE_ARGOCD_BASE_URL", ""))
    _check_registry(_REGISTRY, endpoint)
    return StdioTransport(
        command=_NODE,
        args=[_ENTRYPOINT, "stdio"],
        env={
            "ARGOCD_BASE_URL": endpoint,
            "ARGOCD_API_TOKEN": "",  # Never inherit a broad default token.
            "ARGOCD_TOKEN_REGISTRY_PATH": str(_REGISTRY),
            "MCP_READ_ONLY": "true",
            "NODE_TLS_REJECT_UNAUTHORIZED": "1",
        },
    )


def mount(mcp: FastMCP, *, synthetic_backend: FastMCP | None = None) -> None:
    """Mount reviewed status tools; synthetic backend bypasses secret startup."""
    backend = synthetic_backend if synthetic_backend is not None else _transport()
    proxy = create_proxy(backend)
    # Parent middleware authorizes tool calls, not resource/prompt enumeration.
    proxy.disable(components={"resource", "template", "prompt"})
    mcp.mount(proxy, namespace="argocd")
    mcp.add_transform(
        ToolTransform(
            {
                f"argocd_{name}": ToolTransformConfig(tags={"read"})
                for name in _READ_TOOLS
            }
        )
    )
