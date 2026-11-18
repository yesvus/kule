"""Owner-controlled Gurbet shell via the existing SSH service."""

from __future__ import annotations

import asyncio
import os
from contextlib import suppress
from pathlib import Path

from fastmcp import FastMCP

from ..authz import EXEC
from ..config import Config
from ..redact import redact_text

_KEY = Path("/var/run/kule-host-ssh/id_ed25519")
_KNOWN_HOSTS = Path("/var/run/kule-host-ssh/known_hosts")
_TARGET = "yesvus@100.82.175.48"
_MAX_SCRIPT = 16384
_SSH = "/usr/bin/ssh"


def _argv(seconds: int) -> list[str]:
    return [
        _SSH,
        "-F",
        "/dev/null",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={_KNOWN_HOSTS}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=1",
        "-i",
        str(_KEY),
        _TARGET,
        f"exec /usr/bin/timeout --kill-after=2s {seconds}s /bin/bash --noprofile --norc -s",
    ]


async def _run(script: bytes, seconds: int, max_bytes: int) -> dict:
    # Script is supplied on stdin, not as an argv entry or a local shell.
    proc = await asyncio.create_subprocess_exec(
        *_argv(seconds),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"},
    )
    assert proc.stdin is not None and proc.stdout is not None
    output = bytearray()
    truncated = False

    async def send() -> None:
        try:
            proc.stdin.write(script)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            proc.stdin.close()

    async def receive() -> None:
        nonlocal truncated
        while chunk := await proc.stdout.read(4096):
            remaining = max_bytes - len(output)
            if len(chunk) > remaining:
                truncated = True
            output.extend(chunk[:remaining])

    try:
        async with asyncio.timeout(seconds + 8):
            await asyncio.gather(send(), receive())
            code = await proc.wait()
    finally:
        if proc.returncode is None:
            with suppress(ProcessLookupError):
                proc.kill()
            await proc.communicate()
    return {
        "host": "gurbet",
        "returncode": code,
        "output": redact_text(output.decode("utf-8", errors="replace")),
        "truncated": truncated,
    }


def register(mcp: FastMCP, cfg: Config) -> None:
    if not cfg.tools.exec_enabled or os.environ.get("KULE_HOST_EXEC_ENABLED") != "1":
        return
    if cfg.tools.developer_enabled:
        raise RuntimeError("Gurbet host shell must not share an enabled developer runtime")
    if cfg.tools.timeout_seconds < 15:
        raise RuntimeError("Gurbet host shell requires at least 15 seconds of tool timeout")
    if not (_KEY.is_file() and _KNOWN_HOSTS.is_file() and Path(_SSH).is_file()):
        raise RuntimeError("Gurbet SSH executor prerequisites are missing")

    @mcp.tool(tags={EXEC}, annotations={"readOnlyHint": False, "destructiveHint": True})
    async def host_exec(script: str) -> dict:
        """Execute a bounded Bash script as the trusted Gurbet host operator.

        Broad host and Kubernetes authority; not a sandbox. Never return secret
        material. Do not use this tool from an untrusted developer session.
        """
        if not script.strip() or len(script) > _MAX_SCRIPT:
            raise ValueError("script must be nonempty and at most 16384 UTF-8 bytes")
        try:
            raw = script.encode("utf-8")
        except UnicodeError:
            raise ValueError("script must be UTF-8") from None
        if len(raw) > _MAX_SCRIPT or b"\x00" in raw:
            raise ValueError("invalid script size or encoding")
        seconds = min(90, int(cfg.tools.timeout_seconds) - 10)
        # FastMCP serializes both structured and text results. Leave headroom.
        cap = min(4096, max(128, cfg.tools.max_output_bytes // 16))
        return await _run(raw, seconds, cap)
