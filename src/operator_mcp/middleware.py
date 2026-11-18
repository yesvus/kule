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

from .audit import AuditLog
from .authz import Caller, Policy

ClaimsGetter = Callable[[], Mapping[str, Any] | None]


def claims_from_request() -> Mapping[str, Any] | None:
    token = get_access_token()
    return token.claims if token is not None else None


class OperatorMiddleware(Middleware):
    def __init__(
        self,
        policy: Policy,
        audit: AuditLog,
        kill_switch: Path,
        timeout_seconds: float,
        max_output_bytes: int = 64 * 1024,
        claims_getter: ClaimsGetter = claims_from_request,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.kill_switch = kill_switch
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.claims_getter = claims_getter

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

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        tools = await call_next(context)
        caller = self._caller()
        return [t for t in tools if self.policy.allows(caller, t.tags)[0]]

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
        who = {
            "call_id": call_id,
            "tool": name,
            "user": caller.username if caller else None,
            "sub": caller.subject if caller else None,
        }

        if self.kill_switch.exists():
            await self._audit("denied", reason="kill switch", args=audit_args, **who)
            raise AuthorizationError("operator-mcp is disabled by the kill switch")

        tool = None
        if context.fastmcp_context is not None:
            tool = await context.fastmcp_context.fastmcp.get_tool(name)
        if tool is None:
            await self._audit("denied", reason="unknown tool", args=audit_args, **who)
            raise AuthorizationError(f"tool '{name}' is not available")

        ok, reason = self.policy.allows(caller, tool.tags)
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

        tier = self.policy.tier_of(tool.tags)
        await self._audit("call", tier=tier, args=audit_args, **who)
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
