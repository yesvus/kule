"""Deny-by-default, group-based authorization for tool tiers.

Each tool carries exactly one tier tag. The read, operate and exec tiers
require the operator group; exec also requires its own group and enablement
flag. The workspace tier requires its own group and explicit enablement. A
separately gated non-operator developer can be admitted to *only* the
workspace tier after credential isolation. Anki read and write tiers require
their respective Anki groups independently of operator membership. Untagged
tools are never callable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

READ, OPERATE, EXEC, WORKSPACE = "read", "operate", "exec", "workspace"
ANKI_READ, ANKI_WRITE = "anki_read", "anki_write"
TIERS = (READ, OPERATE, EXEC, WORKSPACE, ANKI_READ, ANKI_WRITE)


@dataclass(frozen=True)
class Caller:
    subject: str
    username: str
    groups: frozenset[str]


def normalize_groups(raw: Any) -> frozenset[str]:
    """Accept a string or a list of strings; anything else means no groups."""
    if isinstance(raw, str):
        return frozenset([raw])
    if isinstance(raw, list):
        return frozenset(g for g in raw if isinstance(g, str))
    return frozenset()


@dataclass(frozen=True)
class Policy:
    required_group: str
    exec_group: str
    exec_enabled: bool
    groups_claim: str = "groups"
    workspace_group: str = "mcp-workspace"
    workspace_enabled: bool = False
    developer_group: str = "mcp-developers"
    developer_enabled: bool = False
    anki_read_group: str = "mcp-anki-read"
    anki_write_group: str = "mcp-anki-write"

    def __post_init__(self) -> None:
        for name in (
            "required_group",
            "exec_group",
            "workspace_group",
            "developer_group",
            "anki_read_group",
            "anki_write_group",
            "groups_claim",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.exec_enabled, bool):
            raise ValueError("exec_enabled must be a bool")
        if (
            len(
                {
                    self.required_group,
                    self.exec_group,
                    self.workspace_group,
                    self.developer_group,
                    self.anki_read_group,
                    self.anki_write_group,
                }
            )
            != 6
        ):
            raise ValueError("authorization groups must differ")
        if not isinstance(self.workspace_enabled, bool):
            raise ValueError("workspace_enabled must be a bool")
        if not isinstance(self.developer_enabled, bool):
            raise ValueError("developer_enabled must be a bool")

    def caller_from_claims(self, claims: Mapping[str, Any] | None) -> Caller | None:
        if not claims:
            return None
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            return None
        groups = normalize_groups(claims.get(self.groups_claim))
        username = claims.get("preferred_username") or claims.get("email") or sub
        return Caller(subject=sub, username=str(username), groups=groups)

    def tier_of(self, tags: Iterable[str]) -> str | None:
        found = [t for t in tags if t in TIERS]
        return found[0] if len(found) == 1 else None

    def allows(self, caller: Caller | None, tags: Iterable[str]) -> tuple[bool, str]:
        if caller is None:
            return False, "unauthenticated"
        tier = self.tier_of(tags)
        if tier is None:
            return False, "tool has no single tier tag"
        if tier == ANKI_READ:
            if self.anki_read_group not in caller.groups:
                return False, f"caller is not in {self.anki_read_group}"
            return True, "ok"
        if tier == ANKI_WRITE:
            if self.anki_write_group not in caller.groups:
                return False, f"caller is not in {self.anki_write_group}"
            return True, "ok"
        operator = self.required_group in caller.groups
        if tier == WORKSPACE:
            if not self.workspace_enabled:
                return False, "workspace tier is disabled"
            if self.workspace_group not in caller.groups:
                return False, f"caller is not in {self.workspace_group}"
            # Non-operators never inherit READ/OPERATE/EXEC from an agent group.
            # Both the independent group and the explicit feature gate are needed.
            if not operator:
                if not self.developer_enabled:
                    return False, "developer workspace access is disabled"
                if self.developer_group not in caller.groups:
                    return False, "caller is not in developer group"
            return True, "ok"
        if not operator:
            return False, f"caller is not in {self.required_group}"
        if tier == EXEC:
            if not self.exec_enabled:
                return False, "exec tier is disabled"
            if self.exec_group not in caller.groups:
                return False, f"caller is not in {self.exec_group}"
        return True, "ok"
