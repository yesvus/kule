import pytest

from operator_mcp.authz import EXEC, OPERATE, READ, Policy

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
