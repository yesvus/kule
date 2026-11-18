"""Role, capability and target authorization for #23 LEG 3 (source-only).

These tests prove the trust boundary in source: roles come from authenticated
groups/claims, Developer and Break-glass cannot borrow Operator capabilities, and
integration calls require an enabled registry entry plus exact targets.
"""

from __future__ import annotations

import math
import time

import mcp_types as mt
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from fastmcp.utilities.versions import VersionSpec

from operator_mcp.authz import Policy, Role
from operator_mcp.config import ConfigError, load_config
from operator_mcp.integrations import (
    Capability,
    Integration,
    IntegrationRegistry,
    capability_tag,
    integration_tag,
    is_integration_tool,
)
from operator_mcp.middleware import _requested_version
from operator_mcp.server import build_server

NOW = 1_700_000_000.0
DEV = "mcp-developers"


class ExpiringClaims:
    """Claims getter that expires a break-glass grant after the Nth read."""

    def __init__(self) -> None:
        self.remaining: int | None = None

    def arm(self, reads: int) -> None:
        self.remaining = reads

    def __call__(self) -> dict:
        expired = False
        if self.remaining is not None:
            if self.remaining <= 0:
                expired = True
            else:
                self.remaining -= 1
        return {
            "sub": "owner",
            "groups": ["mcp-breakglass"],
            "breakglass_exp": time.time() - 1 if expired else time.time() + 60,
        }


def policy(**overrides) -> Policy:
    base = dict(
        required_group="ops",
        exec_group="ops-exec",
        exec_enabled=False,
        workspace_group="mcp-workspace",
        workspace_enabled=True,
        developer_group=DEV,
        developer_enabled=True,
        developer_isolation_verified=True,
        breakglass_group="mcp-breakglass",
        breakglass_enabled=True,
        breakglass_max_ttl_seconds=600,
    )
    base.update(overrides)
    return Policy(**base)


def caller(p: Policy, groups, **claims):
    return p.caller_from_claims({"sub": "agent", "groups": groups, **claims})


def roles(p: Policy, groups, **claims) -> frozenset[Role]:
    return p.roles(caller(p, groups, **claims), now=NOW)


def openhands(**overrides) -> Integration:
    base = dict(
        name="openhands",
        enabled=True,
        backend_identity="canvas/openhands",
        capabilities=frozenset({Capability.WORKER_LAUNCH, Capability.WORKER_STATUS}),
        targets={
            "repository": frozenset({"yesvus/kule"}),
            "acp_profile": frozenset({"opencode"}),
        },
    )
    base.update(overrides)
    return Integration(**base)


def tags(capability: Capability = Capability.WORKER_LAUNCH, name: str = "openhands") -> set[str]:
    return {integration_tag(name), capability_tag(capability)}


def authorized(
    registry: IntegrationRegistry,
    roles,
    tag_set,
    arguments: dict,
    parameter_names=None,
):
    """Call authorize with an explicit schema; the default mirrors tool args."""
    return registry.authorize(
        roles,
        tag_set,
        arguments,
        parameter_names=set(arguments) if parameter_names is None else parameter_names,
    )


# --- role assignment ---------------------------------------------------------


def test_roles_come_from_groups():
    p = policy()
    assert roles(p, ["ops"]) == {Role.OPERATOR}
    assert roles(p, [DEV]) == {Role.DEVELOPER}
    assert roles(p, ["mcp-breakglass"], breakglass_exp=NOW + 60) == {Role.BREAK_GLASS}
    assert roles(p, ["viewers"]) == frozenset()
    assert p.roles(None, now=NOW) == frozenset()


def test_developer_role_requires_enablement_and_isolation_gate():
    assert roles(policy(developer_isolation_verified=False), [DEV]) == frozenset()
    assert roles(policy(developer_enabled=False), [DEV]) == frozenset()
    # The legacy workspace shell path is the same shared-UID/HOME exposure as
    # the canonical Developer role, so it must not bypass the isolation gate.
    legacy = policy(developer_isolation_verified=False)
    assert legacy.allows(caller(legacy, [DEV, "mcp-workspace"]), {"workspace"})[0] is False


def test_breakglass_requires_separate_activation_and_fresh_expiry():
    p = policy()
    assert roles(p, ["mcp-breakglass"], breakglass_exp=NOW + 300) == {Role.BREAK_GLASS}
    assert roles(p, ["mcp-breakglass"], breakglass_exp=NOW - 1) == frozenset()
    assert roles(p, ["mcp-breakglass"], breakglass_exp=NOW + 601) == frozenset()
    assert roles(p, ["mcp-breakglass"]) == frozenset()
    assert (
        roles(policy(breakglass_enabled=False), ["mcp-breakglass"], breakglass_exp=NOW + 60)
        == set()
    )
    for malformed in ("soon", True, math.inf, math.nan, -1, 0, 10**400):
        assert roles(p, ["mcp-breakglass"], breakglass_exp=malformed) == frozenset()


def test_requested_version_is_recovered_from_request_meta():
    exact = mt.CallToolRequestParams(name="x", _meta={"fastmcp": {"version": "2"}})
    assert _requested_version(exact) == VersionSpec(eq="2")
    ranged = mt.CallToolRequestParams(
        name="x", _meta={"fastmcp": {"version": {"gte": "1", "lt": "3"}}}
    )
    assert _requested_version(ranged) == VersionSpec(gte="1", lt="3")
    assert _requested_version(mt.CallToolRequestParams(name="x")) is None


def test_model_or_profile_name_never_grants_a_role():
    p = policy()
    claim_extra = {
        "model": "claude-opus-4",
        "agent_profile": "operator",
        "client_id": "kule-operator",
    }
    assert roles(p, [DEV], **claim_extra) == {Role.DEVELOPER}
    assert roles(p, [], **claim_extra) == frozenset()
    assert roles(p, ["ops"], model="inexpensive-model") == {Role.OPERATOR}


def test_breakglass_does_not_inherit_operator_role():
    p = policy()
    assert roles(p, ["mcp-breakglass"], breakglass_exp=NOW + 60) == {Role.BREAK_GLASS}


def test_policy_rejects_collapsed_roles_and_bad_ttl():
    with pytest.raises(ValueError, match="must differ"):
        policy(breakglass_group="ops")
    with pytest.raises(ValueError, match="breakglass_max_ttl_seconds"):
        policy(breakglass_max_ttl_seconds=30)
    with pytest.raises(ValueError, match="developer_isolation_verified"):
        policy(developer_isolation_verified="true")


def test_disabled_breakglass_does_not_break_legacy_group_name(tmp_path):
    # A legacy deployment may already use the default break-glass group name
    # for another role. It must keep loading while break-glass stays off.
    cfg_path = tmp_path / "c.toml"
    cfg_path.write_text(
        """
[server]
public_url = "https://mcp.example.com"
[auth]
oidc_config_url = "https://id.example.com/.well-known/openid-configuration"
client_id = "c"
developer_group = "mcp-breakglass"
"""
    )
    env = {
        "OPERATOR_MCP_OIDC_CLIENT_SECRET": "s",
        "OPERATOR_MCP_JWT_SIGNING_KEY": "k" * 32,
    }
    cfg = load_config(cfg_path, env)
    assert cfg.auth.developer_group == "mcp-breakglass"
    assert cfg.tools.breakglass_enabled is False

    legacy_policy = policy(breakglass_enabled=False, breakglass_group="ops")
    assert legacy_policy.roles(caller(legacy_policy, ["ops"]), now=NOW) == {Role.OPERATOR}
    with pytest.raises(ValueError, match="breakglass group must differ"):
        policy(breakglass_enabled=True, breakglass_group="ops")


def test_config_defaults_keep_developer_and_breakglass_off(tmp_path):
    cfg_path = tmp_path / "c.toml"
    cfg_path.write_text(
        """
[server]
public_url = "https://mcp.example.com"
[auth]
oidc_config_url = "https://id.example.com/.well-known/openid-configuration"
client_id = "c"
"""
    )
    env = {
        "OPERATOR_MCP_OIDC_CLIENT_SECRET": "s",
        "OPERATOR_MCP_JWT_SIGNING_KEY": "k" * 32,
    }
    cfg = load_config(cfg_path, env)
    assert cfg.tools.developer_enabled is False
    assert cfg.tools.developer_isolation_verified is False
    assert cfg.tools.breakglass_enabled is False
    assert cfg.tools.breakglass_max_ttl_seconds == 900


def test_config_hard_gate_requires_developer_enablement(tmp_path):
    cfg_path = tmp_path / "c.toml"
    cfg_path.write_text(
        """
[server]
public_url = "https://mcp.example.com"
[auth]
oidc_config_url = "https://id.example.com/.well-known/openid-configuration"
client_id = "c"
[tools]
developer_isolation_verified = true
"""
    )
    env = {
        "OPERATOR_MCP_OIDC_CLIENT_SECRET": "s",
        "OPERATOR_MCP_JWT_SIGNING_KEY": "k" * 32,
    }
    with pytest.raises(
        ConfigError, match="developer_isolation_verified requires developer_enabled"
    ):
        load_config(cfg_path, env)


# --- registry validation -----------------------------------------------------


def test_registry_rejects_duplicate_and_unbounded_entries():
    registry = IntegrationRegistry()
    registry.register(openhands())
    with pytest.raises(ValueError, match="already registered"):
        registry.register(openhands())
    with pytest.raises(ValueError, match="wildcards"):
        openhands(name="wild", targets={"repository": frozenset({"*"})})
    with pytest.raises(ValueError, match="wildcards"):
        openhands(name="prefix", targets={"repository": frozenset({"yesvus/*"})})
    with pytest.raises(ValueError, match="exact targets"):
        openhands(name="unscoped", targets={})
    with pytest.raises(ValueError, match="name"):
        openhands(name="Bad-Name")
    with pytest.raises(ValueError, match="backend_identity"):
        openhands(backend_identity="operator credential")


def test_registry_allows_status_without_targets():
    spec = Integration(
        name="health",
        enabled=True,
        backend_identity="canvas/health",
        capabilities=frozenset({Capability.STATUS_READ}),
        targets={},
    )
    registry = IntegrationRegistry()
    registry.register(spec)
    ok, _ = authorized(registry, {Role.DEVELOPER}, tags(Capability.STATUS_READ, "health"), {})
    assert ok is True


def test_integration_tags_must_be_complete_and_known():
    registry = IntegrationRegistry()
    registry.register(openhands())
    cases = [
        ({}, "exactly one integration tag"),
        ({capability_tag(Capability.WORKER_LAUNCH)}, "exactly one integration tag"),
        ({integration_tag("openhands")}, "exactly one capability tag"),
        (
            {integration_tag("openhands"), integration_tag("other"), "capability:worker.launch"},
            "exactly one integration tag",
        ),
        (
            {integration_tag("missing"), capability_tag(Capability.WORKER_LAUNCH)},
            "unknown integration",
        ),
        ({integration_tag("openhands"), "capability:not.real"}, "unknown capability"),
        (
            {integration_tag("openhands"), capability_tag(Capability.CREDENTIAL_APPLY)},
            "not declared",
        ),
    ]
    for case_tags, expected in cases:
        ok, reason = authorized(registry, {Role.OPERATOR}, case_tags, {})
        assert ok is False
        assert expected in reason
    assert is_integration_tool(case_tags) is True
    assert is_integration_tool({"read"}) is False


def test_disabled_integration_is_denied_for_every_role():
    registry = IntegrationRegistry()
    registry.register(openhands(enabled=False))
    allowed = {
        "repository": "yesvus/kule",
        "acp_profile": "opencode",
    }
    for role in Role:
        assert registry.discovery_allowed({role}, tags())[0] is False
        assert authorized(registry, {role}, tags(), allowed) == (False, "integration is disabled")


# --- exact target and capability denial --------------------------------------


def test_developer_worker_launch_is_limited_to_exact_targets():
    registry = IntegrationRegistry()
    registry.register(openhands())
    allowed = {"repository": "yesvus/kule", "acp_profile": "opencode"}
    assert registry.discovery_allowed({Role.DEVELOPER}, tags()) == (True, "ok")
    assert authorized(registry, {Role.DEVELOPER}, tags(), allowed) == (True, "ok")
    assert authorized(
        registry, {Role.DEVELOPER}, tags(), {**allowed, "repository": "yesvus/ops"}
    ) == (False, "target repository is not allowed")
    assert authorized(
        registry, {Role.DEVELOPER}, tags(), {**allowed, "acp_profile": "claude-code"}
    ) == (False, "target acp_profile is not allowed")
    assert authorized(registry, {Role.DEVELOPER}, tags(), {"repository": "yesvus/kule"}) == (
        False,
        "target acp_profile is not allowed",
    )
    assert authorized(registry, {Role.DEVELOPER}, tags(), {**allowed, "repository": 42}) == (
        False,
        "target repository is not allowed",
    )


def test_undeclared_tool_argument_fails_closed():
    registry = IntegrationRegistry()
    registry.register(openhands())
    allowed = {"repository": "yesvus/kule", "acp_profile": "opencode"}

    # Supplied argument with no policy entry is rejected even though both
    # declared targets are valid.
    assert authorized(
        registry,
        {Role.DEVELOPER},
        tags(),
        {**allowed, "host": "karga"},
    ) == (False, "tool argument is not declared by integration policy")

    # The full schema is checked, not only the supplied arguments: an optional
    # undeclared target must also fail closed.
    assert authorized(
        registry,
        {Role.DEVELOPER},
        tags(),
        allowed,
        parameter_names={"repository", "acp_profile", "host"},
    ) == (False, "tool argument is not declared by integration policy")

    # A declared target missing from the schema indicates a mismatched tool.
    assert authorized(
        registry,
        {Role.DEVELOPER},
        tags(),
        allowed,
        parameter_names={"repository"},
    ) == (False, "tool argument is not declared by integration policy")

    # No schema means the policy cannot prove the tool's scope.
    assert registry.authorize({Role.DEVELOPER}, tags(), allowed) == (
        False,
        "tool schema is unavailable",
    )


def test_non_target_inputs_are_explicit_and_scoped():
    registry = IntegrationRegistry()
    registry.register(
        Integration(
            name="hostops",
            enabled=True,
            backend_identity="executor/host",
            capabilities=frozenset({Capability.HOST_EXEC}),
            targets={"host": frozenset({"karga"})},
            inputs=frozenset({"script"}),
        )
    )
    hostops = tags(Capability.HOST_EXEC, "hostops")
    args = {"host": "karga", "script": "uname -a"}
    assert authorized(
        registry,
        {Role.OPERATOR},
        hostops,
        args,
        parameter_names={"host", "script"},
    ) == (True, "ok")
    assert authorized(
        registry,
        {Role.OPERATOR},
        hostops,
        {**args, "cwd": "/tmp"},
        parameter_names={"host", "script", "cwd"},
    ) == (False, "tool argument is not declared by integration policy")
    with pytest.raises(ValueError, match="input and target argument names"):
        Integration(
            name="overlap",
            enabled=True,
            backend_identity="executor/overlap",
            capabilities=frozenset({Capability.HOST_EXEC}),
            targets={"host": frozenset({"karga"})},
            inputs=frozenset({"host"}),
        )


def test_tag_iterables_are_materialized_once():
    registry = IntegrationRegistry()
    registry.register(openhands())
    allowed = {"repository": "yesvus/kule", "acp_profile": "opencode"}
    assert is_integration_tool(iter([capability_tag(Capability.WORKER_LAUNCH)])) is True
    assert registry.discovery_allowed({Role.DEVELOPER}, iter(tags())) == (True, "ok")
    assert authorized(registry, {Role.DEVELOPER}, iter(tags()), allowed) == (True, "ok")


def test_backend_identity_is_resolved_for_audit_only():
    registry = IntegrationRegistry()
    registry.register(openhands())
    assert registry.describe(tags()) == ("openhands", "canvas/openhands")
    assert registry.describe({integration_tag("missing")}) is None
    assert registry.describe({}) is None


def test_developer_cannot_reach_operator_or_breakglass_capabilities():
    registry = IntegrationRegistry()
    registry.register(
        Integration(
            name="credentials",
            enabled=True,
            backend_identity="executor/credentials",
            capabilities=frozenset({Capability.CREDENTIAL_APPLY}),
            targets={"profile": frozenset({"r2-birted"})},
        )
    )
    registry.register(
        Integration(
            name="recovery",
            enabled=True,
            backend_identity="breakglass/recovery",
            capabilities=frozenset({Capability.BREAKGLASS_RECOVER}),
            targets={"host": frozenset({"karga"})},
        )
    )
    registry.register(
        Integration(
            name="argocd",
            enabled=True,
            backend_identity="cluster/argocd",
            capabilities=frozenset({Capability.ARGOCD_SYNC}),
            targets={"app": frozenset({"kule"})},
        )
    )
    registry.register(
        Integration(
            name="hostexec",
            enabled=True,
            backend_identity="host/karga",
            capabilities=frozenset({Capability.HOST_EXEC}),
            targets={"host": frozenset({"karga"})},
            inputs=frozenset({"script"}),
        )
    )
    creds = tags(Capability.CREDENTIAL_APPLY, "credentials")
    recovery = tags(Capability.BREAKGLASS_RECOVER, "recovery")
    sync = tags(Capability.ARGOCD_SYNC, "argocd")
    host = tags(Capability.HOST_EXEC, "hostexec")
    assert authorized(registry, {Role.DEVELOPER}, creds, {"profile": "r2-birted"})[0] is False
    assert authorized(registry, {Role.OPERATOR}, creds, {"profile": "r2-birted"})[0] is True
    assert authorized(registry, {Role.BREAK_GLASS}, creds, {"profile": "r2-birted"})[0] is False
    assert authorized(registry, {Role.OPERATOR}, recovery, {"host": "karga"})[0] is False
    assert authorized(registry, {Role.BREAK_GLASS}, recovery, {"host": "karga"})[0] is True
    assert authorized(registry, {Role.DEVELOPER}, recovery, {"host": "karga"})[0] is False
    # Developer denial must also cover the Operator-only Argo sync and host
    # exec capabilities, not only credential apply.
    assert authorized(registry, {Role.DEVELOPER}, sync, {"app": "kule"})[0] is False
    assert authorized(registry, {Role.OPERATOR}, sync, {"app": "kule"})[0] is True
    assert (
        authorized(
            registry,
            {Role.DEVELOPER},
            host,
            {"host": "karga", "script": "true"},
            parameter_names={"host", "script"},
        )[0]
        is False
    )
    assert authorized(
        registry,
        {Role.OPERATOR},
        host,
        {"host": "karga", "script": "true"},
        parameter_names={"host", "script"},
    ) == (True, "ok")


def test_operator_fixture_write_is_target_scoped():
    registry = IntegrationRegistry()
    registry.register(
        Integration(
            name="fixture",
            enabled=True,
            backend_identity="cluster/staging-fixture",
            capabilities=frozenset({Capability.K8S_WRITE}),
            targets={"namespace": frozenset({"kule-staging-fixture"})},
        )
    )
    fixture = tags(Capability.K8S_WRITE, "fixture")
    assert authorized(
        registry, {Role.OPERATOR}, fixture, {"namespace": "kule-staging-fixture"}
    ) == (
        True,
        "ok",
    )
    assert authorized(registry, {Role.OPERATOR}, fixture, {"namespace": "production"}) == (
        False,
        "target namespace is not allowed",
    )
    assert authorized(registry, {Role.OPERATOR}, fixture, {}) == (
        False,
        "target namespace is not allowed",
    )


def test_unknown_roles_and_unauthenticated_callers_fail_closed():
    registry = IntegrationRegistry()
    registry.register(openhands())
    allowed = {"repository": "yesvus/kule", "acp_profile": "opencode"}
    assert registry.discovery_allowed(set(), tags()) == (
        False,
        "no active role grants worker.launch",
    )
    assert registry.discovery_allowed({"root"}, tags())[0] is False
    assert authorized(registry, set(), tags(), allowed)[0] is False
    assert authorized(registry, ["operator"], tags(), allowed) == (True, "ok")


def test_registry_names_are_exposed_without_targets():
    registry = IntegrationRegistry()
    registry.register(openhands())
    assert registry.names == {"openhands"}
    assert registry.get("openhands") is not None
    assert registry.get("missing") is None


# --- middleware integration --------------------------------------------------


def test_requested_version_selector_is_recovered():
    direct = mt.CallToolRequestParams(name="x", _meta={"fastmcp": {"version": "2"}})
    assert _requested_version(direct) == VersionSpec(eq="2")
    ranged = mt.CallToolRequestParams(
        name="x", _meta={"fastmcp": {"version": {"gte": "1", "lt": "2"}}}
    )
    assert _requested_version(ranged) == VersionSpec(gte="1", lt="2")
    assert _requested_version(mt.CallToolRequestParams(name="x")) is None


def build(claims, make_cfg, registry, **tools):
    cfg = make_cfg(**tools)
    mcp = build_server(cfg, claims_getter=claims, integrations=registry)

    @mcp.tool(tags=tags())
    async def openhands_start(repository: str, acp_profile: str) -> dict:
        return {"repository": repository, "acp_profile": acp_profile}

    return cfg, mcp


def audit_events(cfg):
    import json

    return [json.loads(line) for line in cfg.audit.path.read_text().splitlines()]


async def test_developer_tool_discovery_and_target_denial(make_cfg, claims):
    registry = IntegrationRegistry()
    registry.register(openhands())
    cfg, mcp = build(
        claims,
        make_cfg,
        registry,
        developer_enabled=True,
        developer_isolation_verified=True,
    )
    claims.value = {
        "sub": "dev-agent",
        "groups": [DEV],
        "model": "claude-opus-4",
        "agent_profile": "operator",
    }
    async with Client(mcp) as client:
        assert {t.name for t in await client.list_tools()} == {"openhands_start"}
        result = await client.call_tool(
            "openhands_start",
            {"repository": "yesvus/kule", "acp_profile": "opencode"},
        )
        assert result.data["repository"] == "yesvus/kule"
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool(
                "openhands_start",
                {"repository": "yesvus/ops", "acp_profile": "opencode"},
            )
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("note_write", {"name": "x", "text": "y"})
    events = audit_events(cfg)
    calls = [e for e in events if e["event"] == "call"]
    assert calls[0]["integration"] == "openhands"
    assert calls[0]["backend_identity"] == "canvas/openhands"
    denied = [e for e in events if e["event"] == "denied"]
    assert denied[0]["reason"] == "target repository is not allowed"
    assert denied[-1]["roles"] == ["developer"]
    assert not (cfg.tools.scratch_dir / "x.txt").exists()


async def test_middleware_denies_undeclared_target_argument(make_cfg, claims):
    registry = IntegrationRegistry()
    registry.register(openhands())
    cfg = make_cfg(developer_enabled=True, developer_isolation_verified=True)
    mcp = build_server(cfg, claims_getter=claims, integrations=registry)

    @mcp.tool(tags=tags())
    async def unsafe_start(repository: str, acp_profile: str, host: str) -> dict:
        return {"host": host}

    claims.value = {"sub": "dev-agent", "groups": [DEV]}
    async with Client(mcp) as client:
        # Discovery only sees role/capability, so the unsafe schema is listed.
        assert {t.name for t in await client.list_tools()} == {"unsafe_start"}
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool(
                "unsafe_start",
                {
                    "repository": "yesvus/kule",
                    "acp_profile": "opencode",
                    "host": "production",
                },
            )
    denied = [e for e in audit_events(cfg) if e["event"] == "denied"]
    assert denied[-1]["reason"] == "tool argument is not declared by integration policy"
    assert denied[-1]["integration"] == "openhands"
    assert denied[-1]["backend_identity"] == "canvas/openhands"


async def test_middleware_authorizes_the_dispatched_tool_version(make_cfg, claims):
    registry = IntegrationRegistry()
    registry.register(openhands())
    registry.register(
        Integration(
            name="credentials",
            enabled=True,
            backend_identity="executor/credentials",
            capabilities=frozenset({Capability.CREDENTIAL_APPLY}),
            targets={"profile": frozenset({"r2-birted"})},
        )
    )
    cfg = make_cfg(developer_enabled=True, developer_isolation_verified=True)
    mcp = build_server(cfg, claims_getter=claims, integrations=registry)

    @mcp.tool(
        name="versioned",
        version="1",
        tags=tags(Capability.WORKER_LAUNCH),
    )
    async def worker_version(repository: str, acp_profile: str) -> dict:
        return {"version": 1, "repository": repository}

    @mcp.tool(
        name="versioned",
        version="2",
        tags=tags(Capability.CREDENTIAL_APPLY, "credentials"),
    )
    async def credential_version(profile: str) -> dict:
        return {"version": 2, "profile": profile}

    claims.value = {"sub": "dev-agent", "groups": [DEV]}
    async with Client(mcp) as client:
        # Version 1 is the Worker capability, but the default name-only call
        # resolves version 2 (credential apply). Do not advertise version 1 as
        # reachable by a plain name call.
        assert "versioned" not in {t.name for t in await client.list_tools()}
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool(
                "versioned",
                {"repository": "yesvus/kule", "acp_profile": "opencode"},
            )
        # An explicit version selector dispatches version 1 and is authorized.
        result = await client.call_tool(
            "versioned",
            {"repository": "yesvus/kule", "acp_profile": "opencode"},
            version="1",
        )
        assert result.data["version"] == 1
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("versioned", {"profile": "r2-birted"}, version="2")


async def test_breakglass_expiry_is_rechecked_before_dispatch(make_cfg):
    registry = IntegrationRegistry()
    registry.register(
        Integration(
            name="recovery",
            enabled=True,
            backend_identity="breakglass/recovery",
            capabilities=frozenset({Capability.BREAKGLASS_RECOVER}),
            targets={"host": frozenset({"karga"})},
        )
    )
    cfg = make_cfg(breakglass_enabled=True)
    claims = ExpiringClaims()
    mcp = build_server(cfg, claims_getter=claims, integrations=registry)
    calls: list[str] = []

    @mcp.tool(tags=tags(Capability.BREAKGLASS_RECOVER, "recovery"))
    async def recover(host: str) -> dict:
        calls.append(host)
        return {"host": host}

    claims.arm(2)
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("recover", {"host": "karga"})
    assert calls == []
    denied = [e for e in audit_events(cfg) if e["event"] == "denied"]
    assert "authorization changed before dispatch" in denied[-1]["reason"]


async def test_developer_without_isolation_gate_sees_nothing(make_cfg, claims):
    registry = IntegrationRegistry()
    registry.register(openhands())
    cfg, mcp = build(claims, make_cfg, registry, developer_enabled=True)
    claims.value = {"sub": "dev-agent", "groups": [DEV]}
    async with Client(mcp) as client:
        assert await client.list_tools() == []
        with pytest.raises(ToolError):
            await client.call_tool(
                "openhands_start",
                {"repository": "yesvus/kule", "acp_profile": "opencode"},
            )
    assert audit_events(cfg)[-1]["event"] == "denied"


async def test_operator_and_missing_registry_behaviour(make_cfg, claims):
    registry = IntegrationRegistry()
    registry.register(openhands())
    _, mcp = build(claims, make_cfg, registry, developer_enabled=True)
    claims.value = {"sub": "owner", "groups": ["ops"]}
    async with Client(mcp) as client:
        assert {t.name for t in await client.list_tools()} == {
            "whoami",
            "note_write",
            "openhands_start",
        }
        assert (
            await client.call_tool(
                "openhands_start",
                {"repository": "yesvus/kule", "acp_profile": "opencode"},
            )
        ).data["acp_profile"] == "opencode"

    # No registry means no integration tool is visible or callable, even for
    # an Operator. Existing tier tools continue to work.
    cfg, mcp = build(claims, make_cfg, IntegrationRegistry())
    claims.value = {"sub": "owner", "groups": ["ops"]}
    async with Client(mcp) as client:
        assert {t.name for t in await client.list_tools()} == {"whoami", "note_write"}
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool(
                "openhands_start",
                {"repository": "yesvus/kule", "acp_profile": "opencode"},
            )
    assert audit_events(cfg)[-1]["reason"] == "unknown integration"


async def test_malformed_integration_tools_fail_closed(make_cfg, claims):
    cfg = make_cfg(developer_enabled=True, developer_isolation_verified=True)
    mcp = build_server(cfg, claims_getter=claims, integrations=IntegrationRegistry())

    # The legacy read tag would make these callable if integration detection
    # regressed and fell back to tier policy; the caller below is an Operator.
    @mcp.tool(tags={integration_tag("openhands"), "read"})
    async def no_capability() -> str:
        return "x"

    @mcp.tool(tags={capability_tag(Capability.WORKER_LAUNCH), "read"})
    async def no_integration() -> str:
        return "x"

    claims.value = {"sub": "owner", "groups": ["ops"]}
    async with Client(mcp) as client:
        assert {t.name for t in await client.list_tools()} == {"whoami", "note_write"}
        for name in ("no_capability", "no_integration"):
            with pytest.raises(ToolError, match="not authorized"):
                await client.call_tool(name, {})


async def test_breakglass_role_is_time_limited_at_call_time(make_cfg, claims):
    registry = IntegrationRegistry()
    registry.register(
        Integration(
            name="recovery",
            enabled=True,
            backend_identity="breakglass/recovery",
            capabilities=frozenset({Capability.BREAKGLASS_RECOVER}),
            targets={"host": frozenset({"karga"})},
        )
    )
    cfg = make_cfg(breakglass_enabled=True)
    mcp = build_server(cfg, claims_getter=claims, integrations=registry)

    @mcp.tool(tags=tags(Capability.BREAKGLASS_RECOVER, "recovery"))
    async def recover(host: str) -> dict:
        return {"host": host}

    claims.value = {
        "sub": "owner",
        "groups": ["mcp-breakglass"],
        "breakglass_exp": time.time() + 60,
    }
    async with Client(mcp) as client:
        assert {t.name for t in await client.list_tools()} == {"recover"}
        assert (await client.call_tool("recover", {"host": "karga"})).data["host"] == "karga"

    claims.value = {
        "sub": "owner",
        "groups": ["mcp-breakglass"],
        "breakglass_exp": time.time() - 1,
    }
    async with Client(mcp) as client:
        assert await client.list_tools() == []
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("recover", {"host": "karga"})
