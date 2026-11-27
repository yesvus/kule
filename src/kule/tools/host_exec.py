"""Bounded host execution through a preconfigured SSH target."""

from __future__ import annotations

import asyncio
import os
import re
import signal
from contextlib import suppress
from pathlib import Path

from fastmcp import FastMCP

from ..authz import EXEC
from ..config import Config
from ..redact import redact_text

_KEY = Path("/var/run/kule-host-ssh/id_ed25519")
_KNOWN_HOSTS = Path("/var/run/kule-host-ssh/known_hosts")
_TARGET_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*@[A-Za-z0-9][A-Za-z0-9.-]*$")


def _configured_target() -> str:
    target = os.environ.get("KULE_HOST_EXEC_TARGET", "")
    if not _TARGET_PATTERN.fullmatch(target):
        raise RuntimeError("KULE_HOST_EXEC_TARGET must be a fixed user@host SSH target")
    return target


_MAX_SCRIPT = 16384
_SSH = "/usr/bin/ssh"
_LOCAL_TIMEOUT_GRACE = 8.0
_KILL_GRACE = 0.5
_KILL_WAIT = 1.0
_DRAIN_TIMEOUT = 0.2


def _effective_timeout_seconds(cfg: Config) -> float:
    return round(min(90.0, float(cfg.tools.timeout_seconds) - 10.0), 6)


def _reported_timeout_seconds(seconds: int | float) -> float:
    return round(float(seconds), 1)


def _format_timeout_seconds(seconds: int | float) -> str:
    return f"{_reported_timeout_seconds(seconds):.1f}s"


def _format_budget_seconds(seconds: int | float) -> str:
    return f"{round(float(seconds), 6):.6f}".rstrip("0").rstrip(".") or "0"


def _argv(seconds: int | float) -> list[str]:
    budget_arg = _format_budget_seconds(seconds)
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
        _configured_target(),
        f"exec /usr/bin/timeout --kill-after=2s {budget_arg}s /bin/bash --noprofile --norc -s",
    ]


def _signal_process_group(proc: asyncio.subprocess.Process, sig: signal.Signals) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError):
        if proc.returncode is None:
            with suppress(ProcessLookupError):
                proc.send_signal(sig)


async def _terminate_process_group(
    proc: asyncio.subprocess.Process,
    wait_task: asyncio.Task[int],
) -> None:
    if proc.returncode is None:
        _signal_process_group(proc, signal.SIGTERM)
        with suppress(TimeoutError):
            await asyncio.wait_for(asyncio.shield(wait_task), timeout=_KILL_GRACE)
    # Always follow up with SIGKILL on the process group so descendants that
    # ignored SIGTERM or outlived the group leader cannot keep running.
    _signal_process_group(proc, signal.SIGKILL)
    if proc.returncode is None:
        with suppress(TimeoutError):
            await asyncio.wait_for(asyncio.shield(wait_task), timeout=_KILL_WAIT)


async def _run(script: bytes, seconds: int | float, max_bytes: int) -> dict:
    budget = round(float(seconds), 6)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + budget
    deadline_reached = False

    def mark_deadline() -> None:
        nonlocal deadline_reached
        deadline_reached = True

    deadline_timer = loop.call_at(deadline, mark_deadline)
    # Script is supplied on stdin, not as an argv entry or a local shell.
    # Start a new session so the subprocess leads its own process group and
    # timeout/cancellation cleanup terminates the entire process tree.
    try:
        proc = await asyncio.create_subprocess_exec(
            *_argv(budget),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"},
        )
    except BaseException:
        deadline_timer.cancel()
        raise
    assert proc.stdin is not None and proc.stdout is not None
    output = bytearray()
    truncated = False

    def append_output(chunk: bytes) -> None:
        nonlocal truncated
        remaining = max_bytes - len(output)
        if len(chunk) > remaining:
            truncated = True
        if remaining > 0:
            output.extend(chunk[:remaining])

    async def send() -> None:
        try:
            proc.stdin.write(script)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            proc.stdin.close()

    async def receive() -> None:
        while chunk := await proc.stdout.read(4096):
            append_output(chunk)

    send_task = asyncio.create_task(send())
    receive_task = asyncio.create_task(receive())
    wait_task = asyncio.create_task(proc.wait())
    timed_out = False
    code: int | None = None
    try:
        try:
            async with asyncio.timeout(budget + _LOCAL_TIMEOUT_GRACE):
                await asyncio.shield(send_task)
                await asyncio.shield(receive_task)
                code = await asyncio.shield(wait_task)
        except TimeoutError:
            timed_out = True
            if not send_task.done():
                send_task.cancel()
                with suppress(asyncio.CancelledError):
                    await send_task
            if not proc.stdin.is_closing():
                proc.stdin.close()
            # Keep receive_task draining stdout/stderr during termination so
            # wait() cannot block on an undrained pipe.
            await _terminate_process_group(proc, wait_task)
            if not receive_task.done():
                with suppress(TimeoutError):
                    await asyncio.wait_for(asyncio.shield(receive_task), timeout=_DRAIN_TIMEOUT)
            code = proc.returncode
        else:
            # GNU timeout forwards the child's own exit code (including 124/137),
            # so only treat the run as timed out once our own deadline has fired.
            if (deadline_reached or loop.time() >= deadline) and code in (124, 137):
                timed_out = True
                _signal_process_group(proc, signal.SIGKILL)
    finally:
        deadline_timer.cancel()
        if not proc.stdin.is_closing():
            proc.stdin.close()
        if proc.returncode is None:
            _signal_process_group(proc, signal.SIGKILL)
            with suppress(TimeoutError):
                await asyncio.wait_for(asyncio.shield(wait_task), timeout=_KILL_WAIT)
        for task in (send_task, receive_task, wait_task):
            if not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
    if timed_out and code in (None, 0):
        code = 124
    return {
        "host": "configured-host",
        "returncode": code,
        "output": redact_text(output.decode("utf-8", errors="replace")),
        "truncated": truncated,
        "timed_out": timed_out,
        "timeout_seconds": _reported_timeout_seconds(budget),
    }


def register(mcp: FastMCP, cfg: Config) -> None:
    if not cfg.tools.exec_enabled or os.environ.get("KULE_HOST_EXEC_ENABLED") != "1":
        return
    _configured_target()
    if cfg.tools.developer_enabled:
        raise RuntimeError("Host shell must not share an enabled developer runtime")
    if cfg.tools.timeout_seconds < 15:
        raise RuntimeError("Host shell requires at least 15 seconds of tool timeout")
    if not (_KEY.is_file() and _KNOWN_HOSTS.is_file() and Path(_SSH).is_file()):
        raise RuntimeError("Host SSH executor prerequisites are missing")

    effective_limit = _format_timeout_seconds(_effective_timeout_seconds(cfg))
    description = (
        f"Execute a bounded Bash script on the configured, authorized host "
        f"(effective timeout: {effective_limit}).\n\n"
        "Broad host and Kubernetes authority; not a sandbox. Never return secret "
        "material. Do not use this tool from an untrusted developer session. "
        f"Scripts exceeding {effective_limit} are terminated and return the "
        "captured partial output with timed_out=true; processes that detach "
        "with setsid or double-fork are not stopped at the deadline."
    )

    @mcp.tool(
        description=description,
        tags={EXEC},
        annotations={"readOnlyHint": False, "destructiveHint": True},
    )
    async def host_exec(script: str) -> dict:
        if not script.strip() or len(script) > _MAX_SCRIPT:
            raise ValueError("script must be nonempty and at most 16384 UTF-8 bytes")
        try:
            raw = script.encode("utf-8")
        except UnicodeError:
            raise ValueError("script must be UTF-8") from None
        if len(raw) > _MAX_SCRIPT or b"\x00" in raw:
            raise ValueError("invalid script size or encoding")
        seconds = _effective_timeout_seconds(cfg)
        # FastMCP serializes both structured and text results. Leave headroom.
        cap = min(4096, max(128, cfg.tools.max_output_bytes // 16))
        return await _run(raw, seconds, cap)
