"""Deny-by-default, group-based authorization for tool tiers and roles.

Each legacy tool carries exactly one tier tag. A caller may use a tier only if the
token's groups claim contains the required group. The ``exec`` tier also requires
its own group and enablement flag. The separate ``workspace`` tier requires the
workspace group and explicit enablement. A separately gated non-operator developer
can be admitted to *only* the workspace tier. Untagged tools are never callable.

The canonical Developer/Operator/Break-glass roles are derived from authenticated
identity claims, never from a model name or client-supplied profile. Role-aware
integrations are additionally constrained by capability and target in
``integrations.py``; the legacy tiers above remain unchanged for existing tools.
"""

from __future__ import annotations

import math
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

READ, OPERATE, EXEC, WORKSPACE = "read", "operate", "exec", "workspace"
TIERS = (READ, OPERATE, EXEC, WORKSPACE)


class Role(StrEnum):
    DEVELOPER = "developer"
    OPERATOR = "operator"
    BREAK_GLASS = "breakglass"


@dataclass(frozen=True)
class Caller:
    subject: str
    username: str
    groups: frozenset[str]
    # Unix seconds from a separately granted break-glass claim. The raw claim is
    # never trusted beyond this bounded timestamp.
    breakglass_expires_at: float | None = None


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
    # Separate hard gate for the general Developer role. Keep false until the
    # shared Tezgah UID/HOME credential isolation in ops#731 is verified.
    developer_isolation_verified: bool = False
    breakglass_group: str = "mcp-breakglass"
    breakglass_enabled: bool = False
    breakglass_max_ttl_seconds: int = 900
    breakglass_expires_claim: str = "breakglass_exp"

    def __post_init__(self) -> None:
        for name in (
            "required_group",
            "exec_group",
            "workspace_group",
            "developer_group",
            "breakglass_group",
            "groups_claim",
            "breakglass_expires_claim",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        core_groups = {
            self.required_group,
            self.exec_group,
            self.workspace_group,
            self.developer_group,
        }
        if len(core_groups) != 4:
            raise ValueError("required, exec, workspace and developer groups must differ")
        # Break-glass is opt-in. A legacy configuration may already reuse the
        # default break-glass name for another group; that must stay valid while
        # break-glass is disabled, but a collision is rejected once enabled.
        if self.breakglass_enabled and self.breakglass_group in core_groups:
            raise ValueError("breakglass group must differ from other role groups")
        for name in ("exec_enabled", "workspace_enabled", "developer_enabled"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a bool")
        if not isinstance(self.developer_isolation_verified, bool):
            raise ValueError("developer_isolation_verified must be a bool")
        if not isinstance(self.breakglass_enabled, bool):
            raise ValueError("breakglass_enabled must be a bool")
        if (
            isinstance(self.breakglass_max_ttl_seconds, bool)
            or not isinstance(self.breakglass_max_ttl_seconds, int)
            or not 60 <= self.breakglass_max_ttl_seconds <= 3600
        ):
            raise ValueError("breakglass_max_ttl_seconds must be an integer from 60 to 3600")

    def caller_from_claims(self, claims: Mapping[str, Any] | None) -> Caller | None:
        if not claims:
            return None
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            return None
        groups = normalize_groups(claims.get(self.groups_claim))
        username = claims.get("preferred_username") or claims.get("email") or sub
        expiry = _timestamp(claims.get(self.breakglass_expires_claim))
        return Caller(
            subject=sub,
            username=str(username),
            groups=groups,
            breakglass_expires_at=expiry,
        )

    def roles(self, caller: Caller | None, now: float | None = None) -> frozenset[Role]:
        """Derive roles from authenticated claims; unknown claims grant nothing.

        A break-glass group is inert unless the feature is enabled, a separate
        expiry claim is present and it lies within the configured maximum TTL.
        """
        if caller is None:
            return frozenset()
        found: set[Role] = set()
        if self.required_group in caller.groups:
            found.add(Role.OPERATOR)
        if (
            self.developer_group in caller.groups
            and self.developer_enabled
            and self.developer_isolation_verified
        ):
            found.add(Role.DEVELOPER)
        expiry = caller.breakglass_expires_at
        if self.breakglass_group in caller.groups and self.breakglass_enabled and expiry:
            current = time.time() if now is None else now
            if current < expiry <= current + self.breakglass_max_ttl_seconds:
                found.add(Role.BREAK_GLASS)
        return frozenset(found)

    def tier_of(self, tags: Iterable[str]) -> str | None:
        found = [t for t in tags if t in TIERS]
        return found[0] if len(found) == 1 else None

    def allows(self, caller: Caller | None, tags: Iterable[str]) -> tuple[bool, str]:
        if caller is None:
            return False, "unauthenticated"
        tier = self.tier_of(tags)
        if tier is None:
            return False, "tool has no single tier tag"
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
                # The legacy workspace tier is the developer's shell path. It
                # must not bypass the same shared-UID/HOME gate as the canonical
                # Developer role.
                if not self.developer_isolation_verified:
                    return False, "developer isolation gate is not verified"
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


def _timestamp(raw: Any) -> float | None:
    """Accept only a finite non-boolean number; malformed claims grant nothing."""
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return None
    try:
        value = float(raw)
    except (OverflowError, TypeError, ValueError):
        # Arbitrarily large integers cannot be represented as a float. Treat
        # them as malformed instead of failing the whole request.
        return None
    return value if math.isfinite(value) and value > 0 else None
