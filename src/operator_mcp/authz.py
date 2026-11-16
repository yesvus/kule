"""Deny-by-default, group-based authorization for tool tiers.

Each tool carries exactly one tier tag. A caller may use a tier only if the
token's groups claim contains the required group (and, for ``exec``, the exec
group too, and exec is enabled in config). Tools without a tier tag are never
callable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

READ, OPERATE, EXEC = "read", "operate", "exec"
TIERS = (READ, OPERATE, EXEC)


@dataclass(frozen=True)
class Caller:
    subject: str
    username: str
    groups: frozenset[str]


@dataclass(frozen=True)
class Policy:
    required_group: str
    exec_group: str
    exec_enabled: bool
    groups_claim: str = "groups"

    def caller_from_claims(self, claims: Mapping[str, Any] | None) -> Caller | None:
        if not claims:
            return None
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            return None
        raw = claims.get(self.groups_claim) or []
        if isinstance(raw, str):
            raw = [raw]
        groups = frozenset(g for g in raw if isinstance(g, str))
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
        if self.required_group not in caller.groups:
            return False, f"caller is not in {self.required_group}"
        if tier == EXEC:
            if not self.exec_enabled:
                return False, "exec tier is disabled"
            if self.exec_group not in caller.groups:
                return False, f"caller is not in {self.exec_group}"
        return True, "ok"
