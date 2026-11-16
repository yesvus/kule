"""Phase-1 tools: prove read and write paths end to end without touching the host."""

from __future__ import annotations

import os
import re
import socket
from datetime import UTC, datetime
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from ..authz import OPERATE, READ, Policy
from ..config import Config
from ..middleware import ClaimsGetter
from ..redact import redact_text

_NOTE_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
MAX_NOTE_BYTES = 4096


def register(mcp: FastMCP, cfg: Config, claims_getter: ClaimsGetter, policy: Policy) -> None:
    @mcp.tool(tags={READ}, annotations={"readOnlyHint": True, "openWorldHint": False})
    def whoami() -> dict:
        """Show who the server thinks you are and which host it runs on."""
        claims = claims_getter() or {}
        caller = policy.caller_from_claims(claims)
        return {
            "user": caller.username if caller else None,
            "subject": caller.subject if caller else None,
            "groups": sorted(caller.groups) if caller else [],
            "host": socket.gethostname(),
            "exec_enabled": cfg.tools.exec_enabled,
        }

    @mcp.tool(
        tags={OPERATE},
        # Overwrites an existing note of the same name.
        annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
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
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, body)
        finally:
            os.close(fd)
        return {
            "written": str(path),
            "bytes": len(body),
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
        }
