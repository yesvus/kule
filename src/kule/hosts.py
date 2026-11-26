"""Explicit host inventory, validation, and immutable HostRegistry."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

# Stable lowercase host identifier; rejects wildcards, slashes, whitespace, and options.
_HOST_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# Strict RFC 1123 hostname (no wildcards, no leading hyphen, no user@host or schemes).
_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_USERNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,63}$")
_FORBIDDEN_CHARS = frozenset("*?[]\x00\r\n\t")


class HostPlatform(StrEnum):
    LINUX = "linux"
    MACOS = "macos"


class HostTransportType(StrEnum):
    SSH = "ssh"


def _validate_host_id(host_id: object) -> str:
    if not isinstance(host_id, str) or not _HOST_ID_RE.fullmatch(host_id) or ".." in host_id:
        raise ValueError(
            "host_id must be a lowercase slug (^[a-z0-9][a-z0-9._-]{0,63}$) without '..'"
        )
    return host_id


def _validate_host_address(host: object) -> str:
    if not isinstance(host, str) or not host or host != host.strip():
        raise ValueError("ssh.host must be a non-empty hostname or IP address")
    if any(ch in _FORBIDDEN_CHARS for ch in host) or len(host) > 253:
        raise ValueError(
            "ssh.host must not contain wildcards, control characters, or exceed 253 chars"
        )
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.fullmatch(host):
            raise ValueError(
                "ssh.host must be an explicit hostname or IP (no wildcards, ports, or user@host)"
            ) from None
        return host
    if ip.is_unspecified:
        raise ValueError("ssh.host must not be an unspecified wildcard address (0.0.0.0 or ::)")
    return host


def _validate_username(user: object) -> str:
    if not isinstance(user, str) or not _USERNAME_RE.fullmatch(user):
        raise ValueError("ssh.user must be a valid SSH username")
    return user


def _validate_path(path: object, name: str) -> Path:
    if not isinstance(path, Path):
        raise ValueError(f"{name} must be a Path")
    raw = str(path)
    if not raw.strip() or any(ch in _FORBIDDEN_CHARS for ch in raw):
        raise ValueError(f"{name} must be a non-empty path without wildcards or control characters")
    return path


def _validate_groups(groups: object, name: str) -> frozenset[str]:
    if not isinstance(groups, frozenset):
        raise ValueError(f"{name} must be a frozenset of strings")
    for group in groups:
        if (
            not isinstance(group, str)
            or not group
            or group != group.strip()
            or any(ch in _FORBIDDEN_CHARS for ch in group)
        ):
            raise ValueError(
                f"{name} entries must be non-empty group names without wildcards or control chars"
            )
    return groups


@dataclass(frozen=True)
class SshTargetConfig:
    host: str
    user: str
    key_path: Path = field(repr=False)
    known_hosts_path: Path
    port: int = 22

    def __post_init__(self) -> None:
        _validate_host_address(self.host)
        _validate_username(self.user)
        _validate_path(self.key_path, "ssh.key_path")
        _validate_path(self.known_hosts_path, "ssh.known_hosts_path")
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
        ):
            raise ValueError("ssh.port must be an integer between 1 and 65535")


@dataclass(frozen=True)
class HostPolicy:
    read_groups: frozenset[str] = frozenset()
    exec_groups: frozenset[str] = frozenset()
    exec_enabled: bool = False

    def __post_init__(self) -> None:
        _validate_groups(self.read_groups, "policy.read_groups")
        _validate_groups(self.exec_groups, "policy.exec_groups")
        if not isinstance(self.exec_enabled, bool):
            raise ValueError("policy.exec_enabled must be a bool")


@dataclass(frozen=True)
class HostConfig:
    host_id: str
    transport: HostTransportType
    platform: HostPlatform
    ssh: SshTargetConfig
    policy: HostPolicy = field(default_factory=HostPolicy)
    description: str = ""

    def __post_init__(self) -> None:
        _validate_host_id(self.host_id)
        if not isinstance(self.transport, HostTransportType):
            raise ValueError("transport must be a HostTransportType")
        if not isinstance(self.platform, HostPlatform):
            raise ValueError("platform must be a HostPlatform")
        if not isinstance(self.ssh, SshTargetConfig):
            raise ValueError("ssh must be an SshTargetConfig")
        if not isinstance(self.policy, HostPolicy):
            raise ValueError("policy must be a HostPolicy")
        if not isinstance(self.description, str) or len(self.description) > 256:
            raise ValueError("description must be a string of at most 256 characters")
        if any(ch in "\x00\r\n" for ch in self.description):
            raise ValueError("description must not contain control characters")

    def public_metadata(self) -> dict[str, Any]:
        """Return non-secret host metadata safe to expose in host_list."""
        return {
            "host_id": self.host_id,
            "transport": self.transport.value,
            "platform": self.platform.value,
            "exec_enabled": self.policy.exec_enabled,
            "description": self.description,
        }


class HostRegistry:
    """Immutable registry of explicitly approved hosts indexed by stable host_id."""

    def __init__(self, hosts: Iterable[HostConfig] = ()) -> None:
        entries: dict[str, HostConfig] = {}
        for host in hosts:
            if not isinstance(host, HostConfig):
                raise ValueError("HostRegistry entries must be HostConfig instances")
            if host.host_id in entries:
                raise ValueError(f"duplicate host_id: {host.host_id!r}")
            entries[host.host_id] = host
        self._hosts = entries

    def get(self, host_id: str) -> HostConfig | None:
        if not isinstance(host_id, str):
            return None
        return self._hosts.get(host_id)

    def require(self, host_id: str) -> HostConfig:
        host = self.get(host_id)
        if host is None:
            raise KeyError(f"unknown host_id: {host_id!r}")
        return host

    def all(self) -> tuple[HostConfig, ...]:
        return tuple(self._hosts.values())

    def host_ids(self) -> tuple[str, ...]:
        return tuple(self._hosts.keys())

    def __len__(self) -> int:
        return len(self._hosts)

    def __bool__(self) -> bool:
        return bool(self._hosts)

    def __contains__(self, host_id: object) -> bool:
        return isinstance(host_id, str) and host_id in self._hosts

    def __iter__(self) -> Iterator[HostConfig]:
        return iter(self._hosts.values())
