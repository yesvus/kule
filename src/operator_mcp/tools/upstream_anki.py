"""Opt-in, narrowly allowlisted AnkiMCP upstream behind Kule authorization."""

from __future__ import annotations

import os
from collections.abc import Sequence

import mcp_types as mt
from fastmcp import FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server import create_proxy
from fastmcp.server.middleware import Middleware
from fastmcp.server.middleware.middleware import CallNext, MiddlewareContext
from fastmcp.server.transforms import ToolTransform
from fastmcp.server.transforms.tool_transform import ToolTransformConfig
from fastmcp.tools.base import Tool, ToolResult

from operator_mcp.authz import ANKI_READ, ANKI_WRITE
from operator_mcp.config import validate_anki_mcp_url

_READ_TOOLS = ("listDecks", "findNotes", "notesInfo")
_WRITE_TOOLS = ("addNotes", "updateNoteFields")
# Reviewed against the official AnkiMCP v0.27.0 tool definitions.
_MAX_BATCH_NOTES = 25


def _error(message: str, code: str) -> ToolResult:
    return ToolResult(
        content=[mt.TextContent(type="text", text=message)],
        meta={"anki_error_code": code},
        is_error=True,
    )


class _AnkiFailureIsolation(Middleware):
    """Keep Anki discovery/calls from taking down Kule's other tools."""

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        try:
            return await call_next(context)
        except Exception:
            return []

    async def on_call_tool(self, context, call_next):
        name = context.message.name.removeprefix("anki_")
        arguments = context.message.arguments or {}
        if name == "addNotes":
            notes = arguments.get("notes")
            if "allowDuplicate" in arguments and arguments["allowDuplicate"] is not False:
                return _error("Anki duplicate creation is disabled", "duplicates_disabled")
            if not isinstance(notes, list) or not 1 <= len(notes) <= _MAX_BATCH_NOTES:
                return _error(
                    f"Anki batches must contain 1 to {_MAX_BATCH_NOTES} notes", "batch_limit"
                )
        if name == "updateNoteFields":
            note = arguments.get("note")
            if isinstance(note, dict) and ("audio" in note or "picture" in note):
                return _error("Anki media URL updates are disabled", "media_url_disabled")
        try:
            result = await call_next(context)
        except Exception:
            return _error("Anki upstream is unavailable or rejected the request", "upstream_error")
        if result.is_error:
            return _error("Anki upstream rejected the request", "upstream_error")
        return result


def mount(mcp: FastMCP, *, synthetic_backend: FastMCP | None = None) -> None:
    """Mount the fixed internal MCP endpoint or a synthetic test backend."""
    if synthetic_backend is None:
        endpoint = validate_anki_mcp_url(os.environ.get("KULE_ANKI_MCP_URL", ""))
        if endpoint is None:
            raise RuntimeError("KULE_ANKI_MCP_URL is required when mounting Anki")
        backend = StreamableHttpTransport(url=endpoint)
    else:
        backend = synthetic_backend

    proxy = create_proxy(backend)
    proxy.disable(components={"resource", "template", "prompt"})
    proxy.add_middleware(_AnkiFailureIsolation())
    mcp.mount(proxy, namespace="anki")
    mcp.add_transform(
        ToolTransform(
            {
                **{f"anki_{name}": ToolTransformConfig(tags={ANKI_READ}) for name in _READ_TOOLS},
                **{f"anki_{name}": ToolTransformConfig(tags={ANKI_WRITE}) for name in _WRITE_TOOLS},
            }
        )
    )
