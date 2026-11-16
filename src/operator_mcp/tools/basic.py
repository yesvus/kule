"""Phase-1 tools: prove read and write paths end to end without touching the host."""

from __future__ import annotations

import re
import socket
from datetime import UTC, datetime
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from ..authz import OPERATE, READ, normalize_groups
from ..config import Config
from ..middleware import ClaimsGetter
from ..redact import redact_text

_NOTE_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
MAX_NOTE_BYTES = 4096


def register(mcp: FastMCP, cfg: Config, claims_getter: ClaimsGetter) -> None:
    @mcp.tool(tags={READ}, annotations={"readOnlyHint": True, "openWorldHint": False})
    def whoami() -> dict:
        """Show who the server thinks you are and which host it runs on."""
        claims = claims_getter() or {}
        groups = normalize_groups(claims.get(cfg.auth.groups_claim))
        return {
            "user": claims.get("preferred_username") or claims.get("email"),
            "subject": claims.get("sub"),
            "groups": sorted(groups),
            "host": socket.gethostname(),
            "exec_enabled": cfg.tools.exec_enabled,
        }

    @mcp.tool(
        tags={OPERATE},
        annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    )
    def note_write(
        name: Annotated[str, Field(description="lowercase letters, digits and dashes")],
        text: Annotated[str, Field(description=f"note body, at most {MAX_NOTE_BYTES} bytes")],
    ) -> dict:
        """Write a short note to the server's scratch directory. Harmless test of write access."""
        if not _NOTE_NAME.fullmatch(name):
            raise ValueError("name must match ^[a-z0-9][a-z0-9-]{0,63}$")
        body = redact_text(text).encode()
        if len(body) > MAX_NOTE_BYTES:
            raise ValueError(f"note is larger than {MAX_NOTE_BYTES} bytes")
        scratch = cfg.tools.scratch_dir
        scratch.mkdir(parents=True, exist_ok=True)
        path = scratch / f"{name}.txt"
        path.write_bytes(body)
        return {
            "written": str(path),
            "bytes": len(body),
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
        }
