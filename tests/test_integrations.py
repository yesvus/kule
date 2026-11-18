"""Role, capability and target authorization for #23 LEG 3 (source-only).

These tests prove the trust boundary in source: roles come from authenticated
groups/claims, Developer and Break-glass cannot borrow Operator capabilities, and
integration calls require an enabled registry entry plus exact targets.
"""

from __future__ import annotations

import math
import time

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

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
from operator_mcp.server import build_server

NOW = 1_700_000_000.0
DEV = "mcp-developers"


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
    # The legacy workspace tier is intentionally unchanged by the new role gate.
    legacy = policy(developer_isolation_verified=False)
    assert legacy.allows(caller(legacy, [DEV, "mcp-workspace"]), {"workspace"})[0] is True


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
    for malformed in ("soon", True, math.inf, math.nan, -1, 0):
        assert roles(p, ["mcp-breakglass"], breakglass_exp=malformed) == frozenset()


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
    ok, _ = registry.authorize({Role.DEVELOPER}, tags(Capability.STATUS_READ, "health"), {})
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
        ok, reason = registry.authorize({Role.OPERATOR}, case_tags, {})
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
        assert registry.authorize({role}, tags(), allowed) == (False, "integration is disabled")


# --- exact target and capability denial --------------------------------------


def test_developer_worker_launch_is_limited_to_exact_targets():
    registry = IntegrationRegistry()
    registry.register(openhands())
    allowed = {"repository": "yesvus/kule", "acp_profile": "opencode"}
    assert registry.discovery_allowed({Role.DEVELOPER}, tags()) == (True, "ok")
    assert registry.authorize({Role.DEVELOPER}, tags(), allowed) == (True, "ok")
    assert registry.authorize(
        {Role.DEVELOPER}, tags(), {**allowed, "repository": "yesvus/ops"}
    ) == (False, "target repository is not allowed")
    assert registry.authorize(
        {Role.DEVELOPER}, tags(), {**allowed, "acp_profile": "claude-code"}
    ) == (False, "target acp_profile is not allowed")
    assert registry.authorize({Role.DEVELOPER}, tags(), {"repository": "yesvus/kule"}) == (
        False,
        "target acp_profile is not allowed",
    )
    assert registry.authorize({Role.DEVELOPER}, tags(), {**allowed, "repository": 42}) == (
        False,
        "target repository is not allowed",
    )


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
    creds = tags(Capability.CREDENTIAL_APPLY, "credentials")
    recovery = tags(Capability.BREAKGLASS_RECOVER, "recovery")
    assert registry.authorize({Role.DEVELOPER}, creds, {"profile": "r2-birted"})[0] is False
    assert registry.authorize({Role.OPERATOR}, creds, {"profile": "r2-birted"})[0] is True
    assert registry.authorize({Role.BREAK_GLASS}, creds, {"profile": "r2-birted"})[0] is False
    assert registry.authorize({Role.OPERATOR}, recovery, {"host": "karga"})[0] is False
    assert registry.authorize({Role.BREAK_GLASS}, recovery, {"host": "karga"})[0] is True
    assert registry.authorize({Role.DEVELOPER}, recovery, {"host": "karga"})[0] is False


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
    assert registry.authorize({Role.OPERATOR}, fixture, {"namespace": "kule-staging-fixture"}) == (
        True,
        "ok",
    )
    assert registry.authorize({Role.OPERATOR}, fixture, {"namespace": "production"}) == (
        False,
        "target namespace is not allowed",
    )
    assert registry.authorize({Role.OPERATOR}, fixture, {}) == (
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
    assert registry.authorize(set(), tags(), allowed)[0] is False
    assert registry.authorize(["operator"], tags(), allowed) == (True, "ok")


def test_registry_names_are_exposed_without_targets():
    registry = IntegrationRegistry()
    registry.register(openhands())
    assert registry.names == {"openhands"}
    assert registry.get("openhands") is not None
    assert registry.get("missing") is None


# --- middleware integration --------------------------------------------------


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
    denied = [e for e in audit_events(cfg) if e["event"] == "denied"]
    assert denied[0]["reason"] == "target repository is not allowed"
    assert denied[-1]["roles"] == ["developer"]
    assert not (cfg.tools.scratch_dir / "x.txt").exists()


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

    @mcp.tool(tags={integration_tag("openhands")})
    async def no_capability() -> str:
        return "x"

    @mcp.tool(tags={capability_tag(Capability.WORKER_LAUNCH)})
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
