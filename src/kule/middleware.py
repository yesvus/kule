"""Authorization, kill switch, timeout and audit for every tool call."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import mcp_types as mt
from fastmcp.exceptions import AuthorizationError, ToolError
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import Tool, ToolResult
from fastmcp.utilities.versions import VersionSpec

from .audit import AuditLog
from .authz import Caller, Policy, Role
from .integrations import IntegrationRegistry, is_integration_tool

ClaimsGetter = Callable[[], Mapping[str, Any] | None]


def claims_from_request() -> Mapping[str, Any] | None:
    token = get_access_token()
    return token.claims if token is not None else None


def _requested_version(message: mt.CallToolRequestParams) -> VersionSpec | None:
    """Recover the version selector FastMCP will use for this dispatch.

    FastMCP carries an explicit ``call_tool(version=...)`` selector in
    ``_meta.fastmcp.version`` and uses the same value for dispatch, so
    authorizing this resolved tool matches the tool that actually runs.
    """
    meta = getattr(message, "meta", None)
    if not isinstance(meta, Mapping):
        return None
    fastmcp_meta = meta.get("fastmcp")
    if not isinstance(fastmcp_meta, Mapping):
        return None
    raw = fastmcp_meta.get("version")
    if isinstance(raw, str) and raw:
        return VersionSpec(eq=raw)
    if isinstance(raw, Mapping):
        fields = {key: raw[key] for key in ("gte", "lt", "eq") if isinstance(raw.get(key), str)}
        if fields:
            return VersionSpec(**fields)
    return None


def _tool_parameter_names(tool: Tool) -> frozenset[str] | None:
    """Return the complete schema argument set, or None when it is unreadable."""
    parameters = tool.parameters
    if not isinstance(parameters, Mapping):
        return None
    properties = parameters.get("properties", {})
    if not isinstance(properties, Mapping):
        return None
    if any(not isinstance(name, str) for name in properties):
        return None
    return frozenset(properties)


class OperatorMiddleware(Middleware):
    def __init__(
        self,
        policy: Policy,
        audit: AuditLog,
        kill_switch: Path,
        timeout_seconds: float,
        max_output_bytes: int = 64 * 1024,
        claims_getter: ClaimsGetter = claims_from_request,
        integrations: IntegrationRegistry | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.kill_switch = kill_switch
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.claims_getter = claims_getter
        self.integrations = integrations

    async def _audit(self, event: str, **fields: Any) -> None:
        # flock + fsync block; keep them off the event loop.
        # Shielded so a cancelled request still finishes its audit record.
        task = asyncio.ensure_future(asyncio.to_thread(self.audit.write, event, **fields))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await asyncio.shield(task)
            raise

    def _caller(self) -> Caller | None:
        return self.policy.caller_from_claims(self.claims_getter())

    def _roles(self, caller: Caller | None) -> frozenset[Role]:
        return self.policy.roles(caller)

    def _update_who(
        self, who: dict[str, Any], caller: Caller | None, roles: frozenset[Role]
    ) -> None:
        who.update(
            user=caller.username if caller else None,
            sub=caller.subject if caller else None,
            roles=sorted(role.value for role in roles),
        )

    def _authorize(
        self,
        tool: Tool,
        caller: Caller | None,
        roles: frozenset[Role],
        args: Mapping[str, Any],
        parameter_names: frozenset[str] | None,
    ) -> tuple[bool, str, str | None]:
        if is_integration_tool(tool.tags):
            # Role/capability/target policy is authoritative for integration
            # tools; legacy tier tags must not widen or bypass it.
            if self.integrations is None:
                return False, "integration registry unavailable", "integration"
            ok, reason = self.integrations.authorize(
                roles, tool.tags, args, parameter_names=parameter_names
            )
            return ok, reason, "integration"
        return (*self.policy.allows(caller, tool.tags), self.policy.tier_of(tool.tags))

    def _annotate_integration(self, tool: Tool, who: dict[str, Any]) -> None:
        if self.integrations is None:
            return
        identity = self.integrations.describe(tool.tags)
        if identity is not None:
            who["integration"], who["backend_identity"] = identity

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)
        caller = self._caller()
        roles = self._roles(caller)
        visible: list[Tool] = []
        defaults: dict[str, Tool | None] = {}
        for tool in tools:
            if is_integration_tool(tool.tags):
                # A name-only call dispatches the highest version. Do not
                # advertise an older version that the same name-only call
                # cannot reach; explicit version selectors are still allowed
                # at call time.
                if tool.name not in defaults:
                    defaults[tool.name] = (
                        await context.fastmcp_context.fastmcp.get_tool(tool.name)
                        if context.fastmcp_context is not None
                        else None
                    )
                default = defaults[tool.name]
                if default is None or default.version != tool.version:
                    continue
                if (
                    self.integrations is not None
                    and self.integrations.discovery_allowed(roles, tool.tags)[0]
                ):
                    visible.append(tool)
            elif self.policy.allows(caller, tool.tags)[0]:
                visible.append(tool)
        return visible

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        call_id = uuid.uuid4().hex[:16]
        name = context.message.name
        args = dict(context.message.arguments or {})
        audit_args = _audit_arguments(name, args)
        caller = self._caller()
        roles = self._roles(caller)
        who = {"call_id": call_id, "tool": name}
        self._update_who(who, caller, roles)

        if self.kill_switch.exists():
            await self._audit("denied", reason="kill switch", args=audit_args, **who)
            raise AuthorizationError("kule is disabled by the kill switch")

        tool = None
        if context.fastmcp_context is not None:
            tool = await context.fastmcp_context.fastmcp.get_tool(
                name, version=_requested_version(context.message)
            )
        if tool is None:
            await self._audit("denied", reason="unknown tool", args=audit_args, **who)
            raise AuthorizationError(f"tool '{name}' is not available")

        # Recompute after the lookup await so a short-lived role is evaluated
        # against the request that is about to be dispatched.
        caller = self._caller()
        roles = self._roles(caller)
        self._update_who(who, caller, roles)
        self._annotate_integration(tool, who)
        parameter_names = _tool_parameter_names(tool)

        ok, reason, tier = self._authorize(tool, caller, roles, args, parameter_names)
        if not ok:
            await self._audit("denied", reason=reason, args=audit_args, **who)
            # Keep the policy detail in the audit record, not in the response.
            raise AuthorizationError("not authorized")

        if name.startswith("argocd_") and args.get("argocdBaseUrl") is not None:
            # Validate BEFORE the normal call audit. The nested proxy also
            # enforces the fixed origin, but it runs after this middleware.
            from .tools.upstream_argocd import _url

            supplied = args["argocdBaseUrl"]
            try:
                if not isinstance(supplied, str) or _url(supplied) != _url(
                    os.environ.get("KULE_ARGOCD_BASE_URL", "")
                ):
                    raise ValueError("unapproved Argo endpoint")
            except (RuntimeError, ValueError):
                await self._audit(
                    "denied", reason="Argo CD endpoint override", args=audit_args, **who
                )
                raise AuthorizationError("Argo CD endpoint override is not permitted") from None

        # Record the authorized attempt before dispatch so a crash or
        # cancellation remains auditable. If the post-wait check below rejects,
        # the following denied record states that call_next never ran.
        await self._audit("call", tier=tier, args=audit_args, **who)

        # The audit write yields. Recheck the same policy immediately before
        # dispatch so a break-glass grant cannot expire in that window.
        caller = self._caller()
        roles = self._roles(caller)
        self._update_who(who, caller, roles)
        ok, reason, _ = self._authorize(tool, caller, roles, args, parameter_names)
        if not ok:
            await self._audit(
                "denied",
                reason=f"authorization changed before dispatch: {reason}",
                args=audit_args,
                **who,
            )
            raise AuthorizationError("not authorized")

        # A kill-switch activation during asynchronous lookup/auditing must
        # also stop the pending call. Already dispatched calls are not cancelled.
        if self.kill_switch.exists():
            await self._audit("denied", reason="kill switch", args=audit_args, **who)
            raise AuthorizationError("kule is disabled by the kill switch")

        start = time.monotonic()
        # The deadline stops awaiting the tool. A synchronous tool already
        # running in a worker thread cannot be interrupted; host tools must
        # enforce their own subprocess timeouts (see README).
        deadline = asyncio.timeout(self.timeout_seconds)
        try:
            async with deadline:
                result = await call_next(context)
        except TimeoutError:
            if not deadline.expired():
                # Raised by the tool itself, not by our deadline.
                await self._audit("error", duration_ms=_ms(start), error="TimeoutError", **who)
                raise
            await self._audit("timeout", duration_ms=_ms(start), **who)
            raise ToolError(f"tool timed out after {self.timeout_seconds:g}s") from None
        except asyncio.CancelledError:
            await self._audit("cancelled", duration_ms=_ms(start), **who)
            raise
        except Exception as exc:
            await self._audit(
                "error", duration_ms=_ms(start), error=type(exc).__name__, detail=str(exc), **who
            )
            raise
        size = _result_size(result)
        if size > self.max_output_bytes:
            await self._audit("oversize", duration_ms=_ms(start), bytes=size, **who)
            raise ToolError(f"tool output exceeds {self.max_output_bytes} bytes")
        if _is_host_exec_timeout(name, result):
            await self._audit(
                "timeout",
                duration_ms=_ms(start),
                bytes=size,
                **_host_exec_timeout_audit_fields(result),
                **who,
            )
        else:
            await self._audit("result", duration_ms=_ms(start), bytes=size, **who)
        return result


def _audit_text_digest(value: Any, max_bytes: int) -> dict[str, Any]:
    """Hash only bounded valid UTF-8 inputs; never allocate or persist huge values."""
    if not isinstance(value, str) or len(value) > max_bytes:
        return {"valid": False, "reason": "type-or-size"}
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return {"valid": False, "reason": "invalid-utf8"}
    if len(encoded) > max_bytes:
        return {"valid": False, "reason": "size"}
    return {"valid": True, "bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def _audit_arguments(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Sanitize Argo origin overrides and hash bounded Tezgah arguments."""
    if tool.startswith("argocd_"):
        sanitized = dict(args)
        sanitized.pop("argocdBaseUrl", None)
        if "argocdBaseUrl" in args:
            sanitized["argocd_base_url_override"] = True
        return sanitized
    if tool == "host_exec":
        metadata = _audit_text_digest(args.get("script"), 16384)
        return {
            "script_bytes": metadata.get("bytes"),
            "script_sha256": metadata.get("sha256"),
            "script_valid": metadata["valid"],
        }
    if tool.startswith("oh_"):
        # Store routing metadata and a prompt digest, never message bodies.
        from .tools.openhands import audit_arguments

        return audit_arguments(tool, args)
    if tool == "workspace_exec":
        metadata = _audit_text_digest(args.get("command"), 4096)
        return {
            "command_bytes": metadata.get("bytes"),
            "command_sha256": metadata.get("sha256"),
            "command_valid": metadata["valid"],
        }
    if tool in ("workspace_write", "workspace_read"):
        metadata = _audit_text_digest(args.get("path"), 240)
        result = {
            "path_bytes": metadata.get("bytes"),
            "path_sha256": metadata.get("sha256"),
            "path_valid": metadata["valid"],
        }
        if tool == "workspace_write":
            body = _audit_text_digest(args.get("text"), 8192)
            result.update({"text_bytes": body.get("bytes"), "text_valid": body["valid"]})
        return result
    return args


def _is_host_exec_timeout(tool: str, result: ToolResult) -> bool:
    if tool != "host_exec":
        return False
    structured = getattr(result, "structured_content", None)
    return isinstance(structured, Mapping) and structured.get("timed_out") is True


def _host_exec_timeout_audit_fields(result: ToolResult) -> dict[str, Any]:
    structured = getattr(result, "structured_content", None)
    if not isinstance(structured, Mapping):
        return {}
    fields: dict[str, Any] = {}
    timeout_seconds = structured.get("timeout_seconds")
    if isinstance(timeout_seconds, int | float) and not isinstance(timeout_seconds, bool):
        fields["timeout_seconds"] = timeout_seconds
    returncode = structured.get("returncode")
    if isinstance(returncode, int) and not isinstance(returncode, bool):
        fields["returncode"] = returncode
    truncated = structured.get("truncated")
    if isinstance(truncated, bool):
        fields["truncated"] = truncated
    return fields


def _result_size(result: ToolResult) -> int:
    """Approximate serialized size of a tool result (content + structured)."""
    parts = [getattr(c, "text", "") or "" for c in (result.content or [])]
    size = sum(len(p.encode()) for p in parts)
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        size += len(json.dumps(structured, default=str).encode())
    return size


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
