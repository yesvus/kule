"""Authorization, kill switch, timeout and audit for every tool call."""

from __future__ import annotations

import asyncio
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
        claims_getter: ClaimsGetter = claims_from_request,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.kill_switch = kill_switch
        self.timeout_seconds = timeout_seconds
        self.claims_getter = claims_getter

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
        caller = self._caller()
        who = {
            "call_id": call_id,
            "tool": name,
            "user": caller.username if caller else None,
            "sub": caller.subject if caller else None,
        }

        if self.kill_switch.exists():
            self.audit.write("denied", reason="kill switch", args=args, **who)
            raise AuthorizationError("operator-mcp is disabled by the kill switch")

        tool = None
        if context.fastmcp_context is not None:
            tool = await context.fastmcp_context.fastmcp.get_tool(name)
        if tool is None:
            self.audit.write("denied", reason="unknown tool", args=args, **who)
            raise AuthorizationError(f"tool '{name}' is not available")

        ok, reason = self.policy.allows(caller, tool.tags)
        if not ok:
            self.audit.write("denied", reason=reason, args=args, **who)
            raise AuthorizationError(f"not authorized: {reason}")

        tier = self.policy.tier_of(tool.tags)
        self.audit.write("call", tier=tier, args=args, **who)
        start = time.monotonic()
        try:
            result = await asyncio.wait_for(call_next(context), timeout=self.timeout_seconds)
        except TimeoutError:
            self.audit.write("timeout", duration_ms=_ms(start), **who)
            raise ToolError(f"tool timed out after {self.timeout_seconds:g}s") from None
        except Exception as exc:
            self.audit.write(
                "error", duration_ms=_ms(start), error=type(exc).__name__, detail=str(exc), **who
            )
            raise
        self.audit.write("result", duration_ms=_ms(start), **who)
        return result


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
