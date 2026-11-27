"""Multi-host MCP tools backed by HostRegistry and HostTransport."""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import FastMCP
from fastmcp.exceptions import AuthorizationError, ToolError
from pydantic import Field

from ..authz import EXEC, HOST_SCOPED, READ, HostOperation, Policy
from ..config import Config
from ..hosts import HostRegistry
from ..middleware import ClaimsGetter
from ..redact import redact_text
from ..ssh_transport import SshHostTransport, _validate_script
from ..transport import HostTransport, TransportError


def _bounded_exec_timeout(tool_timeout_seconds: float) -> float:
    return min(90.0, max(1.0, float(tool_timeout_seconds) - 5.0))


def register(
    mcp: FastMCP,
    cfg: Config,
    claims_getter: ClaimsGetter,
    policy: Policy,
    registry: HostRegistry,
    transport: HostTransport | None = None,
) -> None:
    """Register multi-host inventory, status, and opt-in per-host exec tools."""
    if not registry:
        return

    active_transport: HostTransport = transport if transport is not None else SshHostTransport()

    @mcp.tool(tags={READ}, annotations={"readOnlyHint": True, "openWorldHint": False})
    def host_list() -> dict[str, Any]:
        """List hosts the caller is authorized to inspect (non-secret metadata only)."""
        caller = policy.caller_from_claims(claims_getter())
        authorized = policy.authorized_hosts(caller, registry, HostOperation.READ)
        return {"hosts": [host.public_metadata() for host in authorized]}

    @mcp.tool(tags={READ, HOST_SCOPED}, annotations={"readOnlyHint": True, "openWorldHint": True})
    async def host_status(
        host_id: Annotated[str, Field(description="Explicit host_id from host_list")],
    ) -> dict[str, Any]:
        """Check reachability and basic platform info for an explicitly authorized host."""
        if cfg.kill_switch_path.exists():
            raise AuthorizationError("kule is disabled by the kill switch")
        caller = policy.caller_from_claims(claims_getter())
        ok, _ = policy.allows_host(caller, registry, host_id, HostOperation.READ)
        if not ok:
            raise AuthorizationError("not authorized")
        host = registry.require(host_id)
        timeout = min(15.0, max(1.0, float(cfg.tools.timeout_seconds) - 2.0))
        try:
            status = await active_transport.status(host, timeout_seconds=timeout)
        except TransportError as exc:
            raise ToolError(redact_text(str(exc))) from None
        if not status.reachable:
            raise ToolError(redact_text(status.error or f"host '{host.host_id}' is unreachable"))
        return {
            "host_id": status.host_id,
            "transport": status.transport,
            "platform": status.platform.value,
            "reachable": status.reachable,
            "latency_ms": status.latency_ms,
            "os_info": redact_text(status.os_info) if status.os_info else None,
        }

    if not cfg.tools.exec_enabled or not any(h.policy.exec_enabled for h in registry):
        return
    if cfg.tools.developer_enabled:
        raise RuntimeError("Host shell must not share an enabled developer runtime")

    @mcp.tool(
        tags={EXEC, HOST_SCOPED},
        annotations={"readOnlyHint": False, "destructiveHint": True},
    )
    async def host_exec(
        host_id: Annotated[str, Field(description="Explicit host_id with exec enabled")],
        script: Annotated[
            str,
            Field(description="Bounded shell script (max 16384 UTF-8 bytes)"),
        ],
    ) -> dict[str, Any]:
        """Execute a bounded Bash script on an explicitly authorized host with exec enabled.

        Broad host authority; not a sandbox. Never return secret material.
        """
        if cfg.kill_switch_path.exists():
            raise AuthorizationError("kule is disabled by the kill switch")
        caller = policy.caller_from_claims(claims_getter())
        ok, _ = policy.allows_host(caller, registry, host_id, HostOperation.EXEC)
        if not ok:
            raise AuthorizationError("not authorized")
        host = registry.require(host_id)
        _validate_script(script)

        seconds = _bounded_exec_timeout(cfg.tools.timeout_seconds)
        # FastMCP serializes both structured and text results. Leave headroom.
        cap = min(4096, max(128, cfg.tools.max_output_bytes // 16))
        try:
            result = await active_transport.exec_script(
                host,
                script,
                timeout_seconds=seconds,
                max_output_bytes=cap,
            )
        except TransportError as exc:
            raise ToolError(redact_text(str(exc))) from None

        response: dict[str, Any] = {
            "host_id": result.host_id,
            "transport": result.transport,
            "returncode": result.returncode,
            "output": redact_text(result.output),
            "truncated": result.truncated,
            "timed_out": result.timed_out,
            "duration_ms": result.duration_ms,
        }
        if result.error:
            response["error"] = redact_text(result.error)
        return response
