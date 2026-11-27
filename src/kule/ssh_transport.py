"""Hardened multi-host SSH transport implementing the HostTransport contract."""

from __future__ import annotations

import asyncio
import math
import os
import shlex
import time
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path

from .hosts import HostConfig, HostTransportType
from .redact import redact_text
from .transport import (
    ExecResult,
    HostKeyVerificationError,
    HostStatus,
    HostUnreachableError,
    TransportConfigError,
)

_SSH_BIN = "/usr/bin/ssh"
_MAX_SCRIPT_BYTES = 16384
_MINIMAL_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"}


def _remote_exec_command(timeout_seconds: float) -> str:
    """Build a portable remote bash command with a remote-side timeout bound.

    Uses ``timeout`` when available in PATH (Linux and macOS with coreutils),
    and falls back to a POSIX ``sh`` watchdog (``SIGTERM`` after
    ``ceil(timeout_seconds)``, ``SIGKILL`` 2s later) on stock macOS ARM64.
    """
    bound = max(1, math.ceil(timeout_seconds))
    return (
        "/bin/sh -c '"
        "if command -v timeout >/dev/null 2>&1; then "
        f"exec timeout -k 2 {bound} /bin/bash --noprofile --norc -s; "
        "fi; "
        "exec 3<&0; "
        "/bin/bash --noprofile --norc -s <&3 3<&- & "
        "child=$!; "
        f'( sleep {bound}; kill -TERM "$child" 2>/dev/null; '
        'sleep 2; kill -KILL "$child" 2>/dev/null ) </dev/null >/dev/null 2>&1 & '
        "watchdog=$!; "
        'wait "$child"; rc=$?; '
        'kill "$watchdog" 2>/dev/null; wait "$watchdog" 2>/dev/null; '
        'exit "$rc"\''
    )


_HOST_KEY_ERROR_MARKERS = (
    "host key verification failed",
    "remote host identification has changed",
    "offending",
    "no matching host key",
    "are you sure you want to continue connecting",
)

_SSH_ERROR_PREFIXES = (
    "ssh:",
    "ssh_",
    "kex_exchange_identification:",
    "banner exchange:",
    "connection closed by ",
    "connection reset by ",
    "could not resolve hostname",
    "bad owner or permissions",
    "load key ",
    "permission denied (",
)


def _scrub_error(text: str, host: HostConfig) -> str:
    """Remove local credential paths and redact secrets from transport errors."""
    cleaned = text.replace(str(host.ssh.key_path), "<key_path>").replace(
        str(host.ssh.known_hosts_path), "<known_hosts_path>"
    )
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > 300:
        cleaned = f"{cleaned[:300]}..."
    return redact_text(cleaned)


def _validate_script(script: str) -> bytes:
    if not isinstance(script, str) or not script.strip() or len(script) > _MAX_SCRIPT_BYTES:
        raise ValueError(f"script must be nonempty and at most {_MAX_SCRIPT_BYTES} UTF-8 bytes")
    try:
        raw = script.encode("utf-8")
    except UnicodeError:
        raise ValueError("script must be UTF-8") from None
    if len(raw) > _MAX_SCRIPT_BYTES or b"\x00" in raw:
        raise ValueError("invalid script size or encoding")
    return raw


def _validate_command(command: Sequence[str]) -> str:
    if isinstance(command, (str, bytes)) or not command:
        raise ValueError("command must be a non-empty sequence of strings")
    parts: list[str] = []
    for item in command:
        if not isinstance(item, str) or not item or any(ch in "\x00\r\n" for ch in item):
            raise ValueError("command arguments must be non-empty strings without control chars")
        parts.append(item)
    return shlex.join(parts)


async def _terminate_process(proc: asyncio.subprocess.Process) -> None:
    """Terminate a timed-out SSH subprocess cleanly and reap it."""
    if proc.stdin is not None:
        with suppress(Exception):
            proc.stdin.close()
    if proc.returncode is not None:
        return
    with suppress(ProcessLookupError):
        proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=1.0)
    except TimeoutError:
        with suppress(ProcessLookupError):
            proc.kill()
        with suppress(ProcessLookupError):
            await proc.wait()


async def _read_bounded(
    stream: asyncio.StreamReader,
    max_bytes: int,
    buf: bytearray,
    truncated_ref: list[bool],
) -> None:
    while chunk := await stream.read(4096):
        remaining = max_bytes - len(buf)
        if remaining <= 0:
            truncated_ref[0] = True
            continue
        if len(chunk) > remaining:
            truncated_ref[0] = True
        buf.extend(chunk[:remaining])


class SshHostTransport:
    """Hardened SSH implementation of HostTransport for Linux and macOS ARM64 hosts.

    Timeouts are enforced on both sides: Kule cancels and terminates the local
    SSH client on ``timeout_seconds``, and ``exec_script`` wraps the remote bash
    process in a portable ``timeout`` / POSIX ``sh`` watchdog. Note on residual
    remote-process behavior: terminating the local SSH client or sending
    ``SIGTERM``/``SIGKILL`` to the remote ``/bin/bash`` child does not
    guarantee termination of detached background jobs or grandchildren spawned by
    a script into separate sessions or process groups.
    """

    def __init__(self, *, ssh_bin: str = _SSH_BIN) -> None:
        self._ssh_bin = ssh_bin

    @property
    def transport_name(self) -> str:
        return HostTransportType.SSH.value

    def _validate_host_prereqs(self, host: HostConfig) -> None:
        if host.transport is not HostTransportType.SSH:
            raise TransportConfigError(f"host '{host.host_id}' does not use SSH transport")
        ssh_path = Path(self._ssh_bin)
        if not ssh_path.is_file() or not os.access(ssh_path, os.X_OK):
            raise TransportConfigError("SSH client binary is missing or not executable")
        if not host.ssh.key_path.is_file():
            raise TransportConfigError(f"SSH private key missing for host '{host.host_id}'")
        if not host.ssh.known_hosts_path.is_file():
            raise TransportConfigError(f"SSH known_hosts missing for host '{host.host_id}'")

    def build_argv(
        self,
        host: HostConfig,
        remote_command: str,
        *,
        connect_timeout: int = 5,
    ) -> list[str]:
        """Build a hardened, non-interactive OpenSSH argv for an explicit host target."""
        return [
            self._ssh_bin,
            "-F",
            "/dev/null",
            "-T",
            "-p",
            str(host.ssh.port),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={host.ssh.known_hosts_path}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            f"ConnectTimeout={connect_timeout}",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=1",
            "-i",
            str(host.ssh.key_path),
            "--",
            f"{host.ssh.user}@{host.ssh.host}",
            remote_command,
        ]

    async def _run_ssh(
        self,
        host: HostConfig,
        remote_command: str,
        *,
        stdin_data: bytes | None,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> tuple[int | None, bytes, bytes, bool, bool, int]:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        self._validate_host_prereqs(host)

        connect_timeout = min(5, max(1, int(timeout_seconds)))
        argv = self.build_argv(host, remote_command, connect_timeout=connect_timeout)
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE
                if stdin_data is not None
                else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_MINIMAL_ENV,
            )
        except OSError as exc:
            raise TransportConfigError(
                f"failed to launch SSH client: {exc.__class__.__name__}"
            ) from None

        assert proc.stdout is not None and proc.stderr is not None

        async def _send() -> None:
            if stdin_data is None or proc.stdin is None:
                return
            try:
                proc.stdin.write(stdin_data)
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with suppress(Exception):
                    proc.stdin.close()

        stdout_buf = bytearray()
        stderr_buf = bytearray()
        out_trunc = [False]
        err_trunc = [False]
        timed_out = False
        returncode: int | None = None

        try:
            async with asyncio.timeout(timeout_seconds):
                await asyncio.gather(
                    _send(),
                    _read_bounded(proc.stdout, max_output_bytes, stdout_buf, out_trunc),
                    _read_bounded(proc.stderr, max_output_bytes, stderr_buf, err_trunc),
                )
                returncode = await proc.wait()
        except TimeoutError:
            timed_out = True
            await _terminate_process(proc)
        except asyncio.CancelledError:
            if proc.returncode is None:
                with suppress(ProcessLookupError):
                    proc.kill()
                with suppress(Exception):
                    await asyncio.shield(proc.wait())
            raise
        finally:
            if proc.returncode is None:
                with suppress(ProcessLookupError):
                    proc.kill()
                with suppress(Exception):
                    await proc.wait()

        duration_ms = int((time.monotonic() - start) * 1000)
        return (
            returncode,
            bytes(stdout_buf),
            bytes(stderr_buf),
            out_trunc[0] or err_trunc[0],
            timed_out,
            duration_ms,
        )

    def _classify_ssh_failure(
        self,
        host: HostConfig,
        returncode: int | None,
        stdout_bytes: bytes,
        stderr_bytes: bytes,
        *,
        strict_255: bool = False,
    ) -> None:
        if returncode != 255:
            return
        if not strict_255 and stdout_bytes:
            return
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        lines = [line.strip().lower() for line in stderr_text.splitlines() if line.strip()]
        if any(line.startswith(_HOST_KEY_ERROR_MARKERS) for line in lines):
            raise HostKeyVerificationError(
                f"SSH host key verification failed for host '{host.host_id}'"
            )
        if strict_255 or (
            not stdout_bytes and any(line.startswith(_SSH_ERROR_PREFIXES) for line in lines)
        ):
            detail = _scrub_error(stderr_text, host)
            msg = f"host '{host.host_id}' unreachable" + (f": {detail}" if detail else "")
            raise HostUnreachableError(msg)

    async def status(
        self,
        host: HostConfig,
        *,
        timeout_seconds: float,
    ) -> HostStatus:
        rc, stdout_bytes, stderr_bytes, _, timed_out, duration_ms = await self._run_ssh(
            host,
            "uname -srm",
            stdin_data=None,
            timeout_seconds=timeout_seconds,
            max_output_bytes=512,
        )
        if timed_out:
            raise HostUnreachableError(f"host '{host.host_id}' status check timed out")
        self._classify_ssh_failure(host, rc, stdout_bytes, stderr_bytes, strict_255=True)
        if rc != 0:
            detail = _scrub_error(stderr_bytes.decode("utf-8", errors="replace"), host)
            raise HostUnreachableError(
                f"host '{host.host_id}' status probe failed (exit {rc})"
                + (f": {detail}" if detail else "")
            )
        os_info = redact_text(stdout_bytes.decode("utf-8", errors="replace").strip()) or None
        return HostStatus(
            host_id=host.host_id,
            transport=self.transport_name,
            platform=host.platform,
            reachable=True,
            latency_ms=duration_ms,
            os_info=os_info,
        )

    async def read_command(
        self,
        host: HostConfig,
        command: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ExecResult:
        remote_cmd = _validate_command(command)
        rc, stdout_bytes, stderr_bytes, truncated, timed_out, duration_ms = await self._run_ssh(
            host,
            remote_cmd,
            stdin_data=None,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if timed_out:
            return ExecResult(
                host_id=host.host_id,
                transport=self.transport_name,
                returncode=None,
                output=redact_text(stdout_bytes.decode("utf-8", errors="replace")),
                truncated=truncated,
                timed_out=True,
                duration_ms=duration_ms,
                error=f"command timed out after {timeout_seconds:g}s",
            )
        self._classify_ssh_failure(host, rc, stdout_bytes, stderr_bytes, strict_255=False)
        error = (
            _scrub_error(stderr_bytes.decode("utf-8", errors="replace"), host)
            if rc != 0 and stderr_bytes
            else None
        )
        return ExecResult(
            host_id=host.host_id,
            transport=self.transport_name,
            returncode=rc,
            output=redact_text(stdout_bytes.decode("utf-8", errors="replace")),
            truncated=truncated,
            timed_out=False,
            duration_ms=duration_ms,
            error=error,
        )

    async def exec_script(
        self,
        host: HostConfig,
        script: str,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ExecResult:
        """Execute a bounded Bash script over SSH with both local and remote timeouts.

        Residual remote-process behavior: killing the local SSH client or
        sending ``SIGTERM``/``SIGKILL`` to the remote ``/bin/bash`` child does
        not guarantee termination of detached background jobs or grandchildren
        spawned into separate sessions/process groups.
        """
        raw = _validate_script(script)
        remote_cmd = _remote_exec_command(timeout_seconds)
        rc, stdout_bytes, stderr_bytes, truncated, timed_out, duration_ms = await self._run_ssh(
            host,
            remote_cmd,
            stdin_data=raw,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        if not timed_out:
            self._classify_ssh_failure(host, rc, stdout_bytes, stderr_bytes, strict_255=False)

        combined = stdout_bytes + stderr_bytes
        if len(combined) > max_output_bytes:
            combined = combined[:max_output_bytes]
            truncated = True

        output_text = combined.decode("utf-8", errors="replace")
        output_text = output_text.replace(str(host.ssh.key_path), "<key_path>").replace(
            str(host.ssh.known_hosts_path), "<known_hosts_path>"
        )
        return ExecResult(
            host_id=host.host_id,
            transport=self.transport_name,
            returncode=None if timed_out else rc,
            output=redact_text(output_text),
            truncated=truncated,
            timed_out=timed_out,
            duration_ms=duration_ms,
            error=f"command timed out after {timeout_seconds:g}s" if timed_out else None,
        )
