"""Opt-in maintained Kubernetes MCP backend behind Kule's existing auth boundary.

No second public MCP listener or OAuth server. The backend runs over stdio
inside the same Pod and inherits only a minimal environment. Kubernetes RBAC
remains the enforcement boundary; the upstream server's read_only flag is not.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy
from fastmcp.server.transforms import ToolTransform
from fastmcp.server.transforms.tool_transform import ToolTransformConfig

from operator_mcp.config import validate_k8s_api_url

_BINARY = "/usr/local/bin/kubernetes-mcp-server"
_CONFIG = "/usr/local/share/kule/kubernetes-upstream.toml"
_KUBECONFIG = Path("/tmp/kule-upstream-kubeconfig.json")  # noqa: S108
_TOKEN = Path("/var/run/kule-k8s/token")
_CA = Path("/var/run/kule-k8s/ca.crt")

# Only explicitly reviewed upstream tools get Kule's read tier. Any new tool
# introduced by an upstream version stays untagged and fails closed.
_READ_TOOLS = ("pods_list", "events_list", "pods_log")


def _write_kubeconfig() -> Path:
    """Reference the rotating projected token; never copy its contents."""
    base = validate_k8s_api_url(os.environ.get("KULE_K8S_API_URL", ""))
    if not base or not _TOKEN.is_file() or not _CA.is_file():
        raise RuntimeError("Kule Kubernetes API endpoint and projected identity are required")
    cfg = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {"name": "kule", "cluster": {"server": base, "certificate-authority": str(_CA)}}
        ],
        "users": [{"name": "kule", "user": {"tokenFile": str(_TOKEN)}}],
        "contexts": [{"name": "kule", "context": {"cluster": "kule", "user": "kule"}}],
        "current-context": "kule",
    }
    fd = os.open(_KUBECONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(cfg, stream)
    os.chmod(_KUBECONFIG, 0o600)
    return _KUBECONFIG


def mount(mcp: FastMCP, *, synthetic_backend: FastMCP | None = None) -> None:
    """Mount only reviewed tools; synthetic_backend is for isolated tests."""
    if synthetic_backend is None:
        kubeconfig = _write_kubeconfig()
        target = StdioTransport(
            command=_BINARY,
            args=["--config", _CONFIG],
            # No OAuth client secret / signing key forwarded to the Go backend.
            env={"KUBECONFIG": str(kubeconfig), "HOME": str(_KUBECONFIG.parent)},
        )
    else:
        target = synthetic_backend

    proxy = create_proxy(target)
    # Parent OperatorMiddleware gates tools, not arbitrary resources/prompts.
    # Prevent a future upstream update from exposing those extra surfaces.
    proxy.disable(components={"resource", "template", "prompt"})
    mcp.mount(proxy, namespace="k8s")
    mcp.add_transform(
        ToolTransform({f"k8s_{name}": ToolTransformConfig(tags={"read"}) for name in _READ_TOOLS})
    )
