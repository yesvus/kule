import pytest

from operator_mcp.authz import ANKI_READ, ANKI_WRITE, EXEC, OPERATE, READ, Policy

P = Policy(required_group="ops", exec_group="ops-exec", exec_enabled=True)


def caller(groups, sub="u"):
    return P.caller_from_claims({"sub": sub, "groups": groups})


def test_no_claims_or_sub_is_unauthenticated():
    assert P.caller_from_claims(None) is None
    assert P.caller_from_claims({}) is None
    assert P.caller_from_claims({"groups": ["ops"]}) is None
    assert P.caller_from_claims({"sub": "", "groups": ["ops"]}) is None
    assert P.allows(None, {READ}) == (False, "unauthenticated")


def test_required_group_gates_every_tier():
    outsider = caller(["viewers"])
    for tier in (READ, OPERATE, EXEC):
        assert P.allows(outsider, {tier})[0] is False


def test_operator_can_read_and_operate_but_not_exec():
    op = caller(["ops"])
    assert P.allows(op, {READ})[0]
    assert P.allows(op, {OPERATE})[0]
    assert P.allows(op, {EXEC}) == (False, "caller is not in ops-exec")


def test_exec_needs_both_groups_and_enabled_flag():
    both = caller(["ops", "ops-exec"])
    assert P.allows(both, {EXEC})[0]
    assert P.allows(caller(["ops-exec"]), {EXEC})[0] is False
    off = Policy(required_group="ops", exec_group="ops-exec", exec_enabled=False)
    assert off.allows(both, {EXEC}) == (False, "exec tier is disabled")


def test_tools_without_exactly_one_tier_are_denied():
    op = caller(["ops", "ops-exec"])
    assert P.allows(op, set())[0] is False
    assert P.allows(op, {"misc"})[0] is False
    assert P.allows(op, {READ, EXEC})[0] is False


def test_string_groups_claim_and_non_string_entries():
    c = P.caller_from_claims({"sub": "u", "groups": "ops"})
    assert c.groups == {"ops"}
    c = P.caller_from_claims({"sub": "u", "groups": ["ops", 1, None]})
    assert c.groups == {"ops"}


@pytest.mark.parametrize("raw", [{"ops": True}, 1, True, None, ("ops",)])
def test_non_list_groups_claims_grant_nothing(raw):
    c = P.caller_from_claims({"sub": "u", "groups": raw})
    assert c.groups == frozenset()
    assert P.allows(c, {READ})[0] is False


@pytest.mark.parametrize(("req", "exe"), [("ops", "ops"), ("ops", ""), ("", "x")])
def test_policy_rejects_collapsed_exec_gate(req, exe):
    with pytest.raises(ValueError):
        Policy(required_group=req, exec_group=exe, exec_enabled=True)


def test_policy_rejects_non_string_settings():
    with pytest.raises(ValueError):
        Policy(required_group=5, exec_group="x", exec_enabled=False)
    with pytest.raises(ValueError):
        Policy(required_group="a", exec_group="b", exec_enabled="false")


def test_opt_in_developer_identity_can_only_use_workspace():
    policy = Policy(
        required_group="ops",
        exec_group="ops-exec",
        exec_enabled=True,
        workspace_group="workspace",
        workspace_enabled=True,
        developer_group="low-priv-dev",
        developer_enabled=True,
    )
    c = policy.caller_from_claims(
        {
            "sub": "agent-low",
            "groups": ["low-priv-dev", "workspace"],
        }
    )
    assert policy.allows(c, {"workspace"}) == (True, "ok")
    for tier in (READ, OPERATE, EXEC):
        assert policy.allows(c, {tier})[0] is False
    assert policy.allows(c, {"workspace", READ})[0] is False
    assert policy.allows(c, set())[0] is False


def test_developer_gate_fails_closed_without_both_groups_and_feature_flag():
    base = dict(
        required_group="ops",
        exec_group="ops-exec",
        exec_enabled=False,
        workspace_group="workspace",
        workspace_enabled=True,
        developer_group="low-priv-dev",
    )
    active = Policy(**base, developer_enabled=True)
    dev_only = active.caller_from_claims({"sub": "agent", "groups": ["low-priv-dev"]})
    workspace_only = active.caller_from_claims({"sub": "agent", "groups": ["workspace"]})
    neither = active.caller_from_claims({"sub": "agent", "groups": []})
    for c in (dev_only, workspace_only, neither):
        assert active.allows(c, {"workspace"})[0] is False
    with_both = active.caller_from_claims({"sub": "agent", "groups": ["low-priv-dev", "workspace"]})
    assert Policy(**base, developer_enabled=False).allows(with_both, {"workspace"})[0] is False
    assert (
        Policy(**{**base, "workspace_enabled": False}, developer_enabled=True).allows(
            with_both, {"workspace"}
        )[0]
        is False
    )


def test_developer_gate_does_not_reduce_existing_operator_access():
    p = Policy(
        required_group="ops",
        exec_group="ops-exec",
        exec_enabled=True,
        workspace_group="workspace",
        workspace_enabled=True,
        developer_group="low-priv-dev",
        developer_enabled=True,
    )
    owner = p.caller_from_claims({"sub": "owner", "groups": ["ops", "workspace", "ops-exec"]})
    assert all(p.allows(owner, {tier})[0] for tier in (READ, OPERATE, EXEC, "workspace"))
    base_only = p.caller_from_claims({"sub": "owner", "groups": ["ops"]})
    assert p.allows(base_only, {READ})[0] is True
    assert p.allows(base_only, {"workspace"})[0] is False


def test_developer_group_must_be_distinct_and_enablement_bool():
    with pytest.raises(ValueError):
        Policy("ops", "ops-exec", False, developer_group="ops")
    with pytest.raises(ValueError):
        Policy("ops", "ops-exec", False, developer_group="mcp-workspace")
    with pytest.raises(ValueError):
        Policy("ops", "ops-exec", False, developer_enabled="true")


def test_anki_permissions_are_independent_of_operator_and_each_other():
    policy = Policy(
        required_group="ops",
        exec_group="ops-exec",
        exec_enabled=False,
        anki_read_group="anki-readers",
        anki_write_group="anki-writers",
    )
    operator = policy.caller_from_claims({"sub": "operator", "groups": ["ops"]})
    reader = policy.caller_from_claims({"sub": "reader", "groups": ["anki-readers"]})
    writer = policy.caller_from_claims({"sub": "writer", "groups": ["anki-writers"]})
    assert policy.allows(operator, {ANKI_READ})[0] is False
    assert policy.allows(operator, {ANKI_WRITE})[0] is False
    assert policy.allows(reader, {ANKI_READ}) == (True, "ok")
    assert policy.allows(reader, {ANKI_WRITE})[0] is False
    assert policy.allows(writer, {ANKI_WRITE}) == (True, "ok")
    assert policy.allows(writer, {ANKI_READ})[0] is False


def test_anki_groups_must_be_distinct_from_all_other_groups():
    with pytest.raises(ValueError, match="groups must differ"):
        Policy("ops", "exec", False, anki_read_group="ops")
    with pytest.raises(ValueError, match="groups must differ"):
        Policy("ops", "exec", False, anki_write_group="mcp-anki-read")
