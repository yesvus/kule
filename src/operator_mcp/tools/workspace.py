"""Tezgah-only file/process tools over the maintained Kubernetes MCP backend.

The Pod name is pinned at deployment time. There is no arbitrary Kubernetes
target, API path, host shell, node SSH, or inherited operator observer token.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
from pathlib import Path

from fastmcp import Client, FastMCP
from fastmcp.client.transports import StdioTransport

from ..authz import WORKSPACE
from ..config import Config, validate_k8s_api_url
from ..redact import redact_text
from . import workspace_runner

_TOKEN = Path("/var/run/kule-workspace/token")
_CA = Path("/var/run/kule-workspace/ca.crt")
_CONFIG = Path("/tmp/kule-workspace-kubeconfig.json")  # noqa: S108 (O_NOFOLLOW, 0600)
_BACKEND_CONFIG = "/usr/local/share/kule/kubernetes-workspace.toml"
_BINARY = "/usr/local/bin/kubernetes-mcp-server"
_POD_PATTERN = re.compile(r"coder-[a-z0-9-]+-[a-z0-9]{5}")
_MARKER = workspace_runner.MARKER


def _target() -> tuple[str, str]:
    api_url = validate_k8s_api_url(os.environ.get("KULE_WORKSPACE_API_URL", ""))
    pod = os.environ.get("KULE_WORKSPACE_POD", "")
    if not api_url or not _POD_PATTERN.fullmatch(pod):
        raise RuntimeError(
            "workspace requires an explicit Kubernetes API origin and pinned Coder Pod"
        )
    if not _TOKEN.is_file() or not _CA.is_file():
        raise RuntimeError("workspace-only projected ServiceAccount identity is not mounted")
    return api_url, pod


def _write_kubeconfig(api_url: str) -> None:
    config = {
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "workspace", "cluster": {
            "server": api_url, "certificate-authority": str(_CA)
        }}],
        "users": [{"name": "workspace", "user": {"tokenFile": str(_TOKEN)}}],
        "contexts": [{"name": "workspace", "context": {
            "cluster": "workspace", "user": "workspace", "namespace": "coder"
        }}],
        "current-context": "workspace",
    }
    fd = os.open(_CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(config, stream)
    os.chmod(_CONFIG, 0o600)


async def _invoke(pod: str, operation: str, payload: dict, timeout: float) -> dict:
    data = base64.b64encode(json.dumps(payload).encode()).decode()
    # No shell interpolation at the MCP layer. Only the runner's explicit
    # exec operation invokes a shell *inside the selected dev container*.
    arguments = {
        "name": pod, "namespace": "coder", "container": "dev",
        "command": ["python3", "-c", Path(workspace_runner.__file__).read_text(),
                    operation, data],
    }
    transport = StdioTransport(
        command=_BINARY, args=["--config", _BACKEND_CONFIG],
        env={"HOME": str(_CONFIG.parent)},
    )
    async with asyncio.timeout(min(20.0, max(1.0, timeout - 1.0))):
        async with Client(transport) as client:
            result = await client.call_tool("pods_exec", arguments)
    if result.is_error:
        raise RuntimeError("workspace upstream refused the command")
    raw = "\n".join(getattr(item, "text", "") for item in result.content)
    if _MARKER not in raw:
        raise RuntimeError("workspace command returned no valid result marker")
    try:
        decoded = json.JSONDecoder().raw_decode(raw.split(_MARKER, 1)[1])[0]
    except ValueError:
        raise RuntimeError("workspace returned malformed JSON") from None
    if not isinstance(decoded, dict):
        raise RuntimeError("workspace returned an invalid result")
    if "error" in decoded:
        raise RuntimeError(f"workspace operation failed ({decoded['error']})")
    return decoded


def register(mcp: FastMCP, cfg: Config) -> None:
    if not cfg.tools.workspace_enabled:
        return
    api_url, pod = _target()
    _write_kubeconfig(api_url)

    @mcp.tool(tags={WORKSPACE}, annotations={"readOnlyHint": False, "openWorldHint": False})
    async def workspace_exec(command: str) -> dict:
        """Run a short bounded command only in the pinned Tezgah dev container.

        Full developer-user rights inside Tezgah: not a sandbox for secret files.
        """
        if not isinstance(command, str) or not command.strip() or len(command.encode()) > 4096:
            raise ValueError("command must be 1..4096 UTF-8 bytes")
        result = await _invoke(pod, "exec", {"command": command}, cfg.tools.timeout_seconds)
        result["stdout"] = redact_text(result.get("stdout", ""))
        return result

    @mcp.tool(tags={WORKSPACE}, annotations={"readOnlyHint": True, "openWorldHint": False})
    async def workspace_read(path: str) -> dict:
        """Read a bounded UTF-8 file below /workspace (no hidden files or symlinks)."""
        if not isinstance(path, str) or len(path) > 240:
            raise ValueError("invalid path")
        result = await _invoke(pod, "read", {"path": path}, cfg.tools.timeout_seconds)
        result["text"] = redact_text(result.get("text", ""))
        return result

    @mcp.tool(tags={WORKSPACE}, annotations={"readOnlyHint": False, "openWorldHint": False})
    async def workspace_write(path: str, text: str) -> dict:
        """Atomically write <=8192 UTF-8 bytes in /workspace; no path traversal."""
        if not isinstance(path, str) or len(path) > 240 or not isinstance(text, str):
            raise ValueError("invalid workspace write")
        if len(text.encode()) > workspace_runner.MAX_BYTES:
            raise ValueError("workspace write limit exceeded")
        return await _invoke(pod, "write", {"path": path, "text": text}, cfg.tools.timeout_seconds)
