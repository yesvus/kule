"""Transport-independent HostTransport protocol and bounded result types."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .hosts import HostConfig, HostPlatform


class TransportError(RuntimeError):
    """Base error for host transport failures."""


class HostUnreachableError(TransportError):
    """Raised when a configured host cannot be reached."""


class HostKeyVerificationError(TransportError):
    """Raised when SSH host key verification fails."""


class TransportConfigError(TransportError):
    """Raised when transport prerequisites (keys, known_hosts, binaries) are missing or invalid."""


@dataclass(frozen=True)
class HostStatus:
    host_id: str
    transport: str
    platform: HostPlatform
    reachable: bool
    latency_ms: int | None = None
    os_info: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class ExecResult:
    host_id: str
    transport: str
    returncode: int | None
    output: str
    truncated: bool = False
    timed_out: bool = False
    cancelled: bool = False
    duration_ms: int = 0
    error: str | None = None


@runtime_checkable
class HostTransport(Protocol):
    """Async transport contract for host reachability, bounded reads, and opt-in exec."""

    @property
    def transport_name(self) -> str: ...

    async def status(
        self,
        host: HostConfig,
        *,
        timeout_seconds: float,
    ) -> HostStatus: ...

    async def read_command(
        self,
        host: HostConfig,
        command: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ExecResult: ...

    async def exec_script(
        self,
        host: HostConfig,
        script: str,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ExecResult: ...
