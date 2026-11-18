"""Role, capability and exact-target authorization for opt-in integrations.

This is the small contract shared by Kule integrations (Kubernetes, Argo CD,
Tezgah, OpenHands, credential facades). An integration declares its name, backend
identity, enabled flag, capabilities and the exact argument values it accepts.
Its tools carry two extra tags::

    @mcp.tool(tags={integration_tag("openhands"), capability_tag(Capability.WORKER_LAUNCH)})
    async def openhands_start(repository: str, acp_profile: str) -> dict: ...

The registry then enforces, at discovery and call time:

* the integration is registered and explicitly enabled;
* the authenticated caller has a role that includes the capability;
* every tool argument is declared as either an exact target or an explicitly
  non-target input, so an undeclared routing argument fails closed;
* every declared target argument is present and exactly allowlisted.

Targets are exact strings, never prefixes, globs or model-supplied aliases. A
caller cannot gain a role by claiming a model, client or ACP profile name; roles
come from ``authz.Policy.roles`` and authenticated groups/claims only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from .authz import Role

INTEGRATION_TAG_PREFIX = "integration:"
CAPABILITY_TAG_PREFIX = "capability:"

_NAME = re.compile(r"[a-z][a-z0-9_]{1,31}")
_ARGUMENT = re.compile(r"[a-z][a-z0-9_]{0,63}")


class Capability(StrEnum):
    STATUS_READ = "status.read"
    WORKSPACE_EXEC = "workspace.exec"
    WORKSPACE_READ = "workspace.read"
    WORKSPACE_WRITE = "workspace.write"
    REPO_READ = "repo.read"
    REPO_WRITE = "repo.write"
    PR_OPEN = "pr.open"
    K8S_READ = "k8s.read"
    K8S_WRITE = "k8s.write"
    ARGOCD_READ = "argocd.read"
    ARGOCD_SYNC = "argocd.sync"
    CREDENTIAL_PLAN = "credential.plan"
    CREDENTIAL_APPLY = "credential.apply"
    HOST_EXEC = "host.exec"
    SCRATCH_WRITE = "scratch.write"
    WORKER_LAUNCH = "worker.launch"
    WORKER_STATUS = "worker.status"
    WORKER_STOP = "worker.stop"
    BREAKGLASS_RECOVER = "breakglass.recover"


_DEVELOPER = frozenset(
    {
        Capability.STATUS_READ,
        Capability.WORKSPACE_EXEC,
        Capability.WORKSPACE_READ,
        Capability.WORKSPACE_WRITE,
        Capability.REPO_READ,
        Capability.REPO_WRITE,
        Capability.PR_OPEN,
        Capability.K8S_READ,
        Capability.WORKER_LAUNCH,
        Capability.WORKER_STATUS,
        Capability.WORKER_STOP,
    }
)
_OPERATOR = _DEVELOPER | frozenset(
    {
        Capability.SCRATCH_WRITE,
        Capability.K8S_WRITE,
        Capability.ARGOCD_READ,
        Capability.ARGOCD_SYNC,
        Capability.CREDENTIAL_PLAN,
        Capability.CREDENTIAL_APPLY,
        Capability.HOST_EXEC,
    }
)
_BREAKGLASS = frozenset({Capability.STATUS_READ, Capability.BREAKGLASS_RECOVER})

# Break-glass is deliberately separate from Operator: it must not become an
# always-on route to ordinary production writes or developer shell access.
ROLE_CAPABILITIES: Mapping[Role, frozenset[Capability]] = MappingProxyType(
    {
        Role.DEVELOPER: _DEVELOPER,
        Role.OPERATOR: _OPERATOR,
        Role.BREAK_GLASS: _BREAKGLASS,
    }
)

# Capabilities that may be exposed without a target argument. Everything else
# must name an exact target so a tool cannot silently widen its scope.
_UNSCOPED = frozenset({Capability.STATUS_READ})


def _role_capabilities(role: object) -> frozenset[Capability]:
    """Fail closed for unknown roles, including unexpected string input."""
    try:
        return ROLE_CAPABILITIES[Role(role)]
    except (KeyError, TypeError, ValueError):
        return frozenset()


def integration_tag(name: str) -> str:
    return f"{INTEGRATION_TAG_PREFIX}{name}"


def capability_tag(capability: Capability) -> str:
    return f"{CAPABILITY_TAG_PREFIX}{Capability(capability).value}"


def is_integration_tool(tags: Iterable[str]) -> bool:
    # Materialize: callers may pass a one-shot iterator and both prefixes must
    # be checked against the same set of tags.
    return any(
        t.startswith(INTEGRATION_TAG_PREFIX) or t.startswith(CAPABILITY_TAG_PREFIX)
        for t in tuple(tags)
    )


@dataclass(frozen=True)
class Integration:
    """One opt-in backend and the exact capabilities/targets it may serve."""

    name: str
    enabled: bool
    backend_identity: str
    capabilities: frozenset[Capability]
    # Argument name -> exact allowlisted values. Every target-bearing argument
    # that the tools accept must be declared here.
    targets: Mapping[str, frozenset[str]] = field(default_factory=dict)
    # Tool arguments that are payload or metadata rather than routing targets.
    # This is an explicit allowlist: an argument in neither targets nor inputs
    # is a policy error, not a pass-through.
    inputs: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _NAME.fullmatch(self.name):
            raise ValueError("integration name must match ^[a-z][a-z0-9_]{1,31}$")
        if not isinstance(self.enabled, bool):
            raise ValueError("integration enabled must be a bool")
        if not isinstance(self.backend_identity, str) or not self.backend_identity.strip():
            raise ValueError("integration backend_identity must be a non-empty identifier")
        if len(self.backend_identity) > 128 or any(c.isspace() for c in self.backend_identity):
            raise ValueError("integration backend_identity must be a short non-secret identifier")
        try:
            capabilities = frozenset(Capability(c) for c in self.capabilities)
        except (TypeError, ValueError):
            raise ValueError("integration capabilities must be known capabilities") from None
        if not capabilities:
            raise ValueError("integration must declare at least one capability")
        if not isinstance(self.targets, Mapping):
            raise ValueError("integration targets must be a mapping")
        targets: dict[str, frozenset[str]] = {}
        for argument, values in self.targets.items():
            if not isinstance(argument, str) or not _ARGUMENT.fullmatch(argument):
                raise ValueError("target arguments must be lowercase identifiers")
            if isinstance(values, str) or not isinstance(values, Iterable):
                raise ValueError(f"target {argument} must be an iterable of exact values")
            exact: set[str] = set()
            for value in values:
                if not isinstance(value, str) or not value or len(value) > 256:
                    raise ValueError(f"target {argument} values must be short strings")
                if value == "*" or "*" in value or any(c.isspace() for c in value):
                    raise ValueError(f"target {argument} must not use wildcards or whitespace")
                if any(ord(c) < 32 for c in value):
                    raise ValueError(f"target {argument} must not contain control characters")
                exact.add(value)
            if not exact:
                raise ValueError(f"target {argument} must not be empty")
            targets[argument] = frozenset(exact)
        if isinstance(self.inputs, str) or not isinstance(self.inputs, Iterable):
            raise ValueError("integration inputs must be an iterable of argument names")
        inputs: set[str] = set()
        for argument in self.inputs:
            if not isinstance(argument, str) or not _ARGUMENT.fullmatch(argument):
                raise ValueError("input arguments must be lowercase identifiers")
            inputs.add(argument)
        if inputs & targets.keys():
            raise ValueError("input and target argument names must differ")
        if capabilities - _UNSCOPED and not targets:
            raise ValueError("target-bearing capabilities require exact targets")
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "targets", MappingProxyType(targets))
        object.__setattr__(self, "inputs", frozenset(inputs))


class IntegrationRegistry:
    """Deny-by-default registry; unknown integrations and capabilities fail closed."""

    def __init__(self) -> None:
        self._integrations: dict[str, Integration] = {}

    def register(self, integration: Integration) -> Integration:
        if not isinstance(integration, Integration):
            raise TypeError("register expects an Integration")
        if integration.name in self._integrations:
            raise ValueError(f"integration {integration.name} is already registered")
        self._integrations[integration.name] = integration
        return integration

    def get(self, name: str) -> Integration | None:
        return self._integrations.get(name)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._integrations)

    def describe(self, tags: Iterable[str]) -> tuple[str, str] | None:
        """Return the enabled integration's name and backend identity for audit."""
        spec, _, _ = self._resolve(tags)
        if spec is None:
            return None
        return spec.name, spec.backend_identity

    def discovery_allowed(self, roles: Iterable[Role], tags: Iterable[str]) -> tuple[bool, str]:
        """Role/capability check used to filter tool discovery; targets not known yet."""
        tags = tuple(tags)
        spec, capability, reason = self._resolve(tags)
        if spec is None:
            return False, reason
        allowed = [role for role in roles if capability in _role_capabilities(role)]
        if not allowed:
            return False, f"no active role grants {capability.value}"
        return True, "ok"

    def authorize(
        self,
        roles: Iterable[Role],
        tags: Iterable[str],
        arguments: Mapping[str, object],
        *,
        parameter_names: Iterable[str] | None = None,
    ) -> tuple[bool, str]:
        """Full call-time check: role, capability, tool schema and exact targets.

        ``parameter_names`` is the tool's complete input schema. An argument that
        is absent from both ``targets`` and ``inputs`` fails closed, so a tool
        cannot add an unchecked routing argument after registration.
        """
        tags = tuple(tags)
        ok, reason = self.discovery_allowed(roles, tags)
        if not ok:
            return False, reason
        spec, capability, _ = self._resolve(tags)
        if spec is None or capability is None:
            return False, "integration policy is incomplete"
        if not isinstance(arguments, Mapping):
            return False, "tool arguments are not a mapping"
        if parameter_names is None:
            return False, "tool schema is unavailable"
        try:
            accepted = set(parameter_names)
        except TypeError:
            return False, "tool schema is malformed"
        if not all(isinstance(name, str) for name in accepted):
            return False, "tool schema is malformed"
        declared = set(spec.targets) | set(spec.inputs)
        if accepted - declared or set(arguments) - accepted:
            return False, "tool argument is not declared by integration policy"
        for argument, allowed in spec.targets.items():
            value = arguments.get(argument)
            if not isinstance(value, str) or value not in allowed:
                return False, f"target {argument} is not allowed"
        return True, "ok"

    def _resolve(self, tags: Iterable[str]) -> tuple[Integration | None, Capability | None, str]:
        # Materialize once: tags may be a one-shot iterator and both prefixes
        # must be resolved against the same values.
        tags = tuple(tags)
        names = [
            t.removeprefix(INTEGRATION_TAG_PREFIX)
            for t in tags
            if t.startswith(INTEGRATION_TAG_PREFIX)
        ]
        capabilities = [
            t.removeprefix(CAPABILITY_TAG_PREFIX)
            for t in tags
            if t.startswith(CAPABILITY_TAG_PREFIX)
        ]
        if len(names) != 1:
            return None, None, "tool must declare exactly one integration tag"
        if len(capabilities) != 1:
            return None, None, "tool must declare exactly one capability tag"
        spec = self._integrations.get(names[0])
        if spec is None:
            return None, None, "unknown integration"
        if not spec.enabled:
            return None, None, "integration is disabled"
        try:
            capability = Capability(capabilities[0])
        except ValueError:
            return None, None, "unknown capability"
        if capability not in spec.capabilities:
            return None, None, "capability is not declared by this integration"
        return spec, capability, "ok"
