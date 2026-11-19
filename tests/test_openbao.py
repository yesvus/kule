"""Source-only tests for the typed OpenBao metadata onboarding interface.

Everything here uses a fake trusted executor. No OpenBao, Kubernetes, token,
credential or network access is required or attempted.
"""

from __future__ import annotations

import json
from dataclasses import fields
from typing import Any

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from operator_mcp.audit import AuditLog
from operator_mcp.authz import Policy
from operator_mcp.middleware import OperatorMiddleware
from operator_mcp.tools import openbao

PROFILE = "developer-github"
PATH = "tezgah/github/yesvus-developer"
CONSUMER = "tezgah-developer"


def metadata(
    *,
    version: int = 0,
    custom: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "current_version": version,
        "created_time": "2026-11-18T00:00:00Z",
        "updated_time": "2026-11-18T00:00:00Z",
        "custom_metadata": {} if custom is None else dict(custom),
        "max_versions": 0,
        "cas_required": False,
        "delete_version_after": "0s",
    }


class FakeExecutor:
    """Minimal in-memory implementation of the reviewed metadata-only contract."""

    def __init__(self, current: dict[str, Any] | None = None) -> None:
        self.current = current
        self.reads: list[tuple[str, str]] = []
        self.reserves: list[tuple[str, str, dict[str, str]]] = []

    async def read_kv_metadata(self, *, mount: str, path: str) -> dict[str, Any] | None:
        self.reads.append((mount, path))
        return self.current

    async def reserve_kv_metadata(
        self, *, mount: str, path: str, custom_metadata: dict[str, str]
    ) -> None:
        self.reserves.append((mount, path, dict(custom_metadata)))
        current_version = 0
        if isinstance(self.current, dict):
            current_version = int(self.current.get("current_version", 0))
        self.current = metadata(version=current_version, custom=dict(custom_metadata))


@pytest.fixture
def config() -> openbao.OpenBaoConfig:
    return openbao.OpenBaoConfig(
        profiles=(
            openbao.OpenBaoProfile(
                name=PROFILE,
                path_prefix="tezgah/github",
                consumers=(CONSUMER,),
                required_keys=("token",),
            ),
            openbao.OpenBaoProfile(
                name="infra-github",
                path_prefix="infra/github",
                consumers=("yesvus-operator",),
            ),
        ),
        ui_secret_url_template="https://bao.example.com/ui/vault/secrets/{mount}/show/{path}",
    )


async def prepare(
    executor: FakeExecutor,
    config: openbao.OpenBaoConfig,
    **overrides: Any,
) -> dict[str, Any]:
    values: dict[str, Any] = {
        "profile": PROFILE,
        "path": PATH,
        "required_keys": ["token"],
        "provider_scope": "github:yesvus/developer",
        "consumer": CONSUMER,
        "expires_at": "2999-12-31",
    }
    values.update(overrides)
    return await openbao.prepare_onboarding(executor, config, **values)


async def test_prepare_reserves_empty_metadata_and_returns_owner_input_url(config):
    executor = FakeExecutor()

    result = await prepare(executor, config)

    assert result["status"] == "awaiting_value"
    assert result["value_state"] == "awaiting_value"
    assert result["reservation_written"] is True
    assert result["value_read"] is False
    assert result["verification"] == "not_performed"
    assert result["ui_url"] == (
        "https://bao.example.com/ui/vault/secrets/kv/show/tezgah/github/yesvus-developer"
    )
    assert result["required_keys"] == ["token"]
    assert result["metadata"]["current_version"] == 0
    assert result["reservation"] == {
        "profile": PROFILE,
        "required_keys": ["token"],
        "provider_scope": "github:yesvus/developer",
        "consumer": CONSUMER,
        "expires_at": "2999-12-31",
    }
    assert result["reservation_matches_profile"] is True
    assert result["expired"] is False
    assert "Do not paste values" in " ".join(result["instructions"])

    assert executor.reads == [("kv", PATH), ("kv", PATH)]
    assert len(executor.reserves) == 1
    mount, path, custom = executor.reserves[0]
    assert (mount, path) == ("kv", PATH)
    assert custom["kule-schema"] == "1"
    assert custom["kule-profile"] == PROFILE
    assert custom["kule-required-keys"] == "token"
    assert custom["kule-provider-scope"] == "github:yesvus/developer"
    assert custom["kule-consumer"] == CONSUMER
    assert custom["kule-expires-at"] == "2999-12-31"

    rendered = json.dumps(result)
    assert "ghp_" not in rendered
    assert "token_value" not in rendered
    assert '"data"' not in rendered


async def test_prepare_refuses_an_existing_value_version_without_writing(config):
    existing = metadata(version=3, custom={"owner": "team"})
    executor = FakeExecutor(existing)

    result = await prepare(executor, config)

    assert result["status"] == "value_present_unverified"
    assert result["value_state"] == "value_present_unverified"
    assert result["reservation_written"] is False
    assert executor.reserves == []
    assert "no metadata was changed" in " ".join(result["instructions"])
    assert result["metadata"]["current_version"] == 3
    # Unknown custom metadata is counted, not echoed as a key/value pair.
    assert '"owner":' not in json.dumps(result)
    assert '"team"' not in json.dumps(result)


async def test_prepare_preserves_unrelated_custom_metadata(config):
    executor = FakeExecutor(metadata(custom={"owner": "team"}))

    await prepare(executor, config)

    custom = executor.reserves[0][2]
    assert custom["owner"] == "team"
    assert custom["kule-profile"] == PROFILE


def existing_reservation(**overrides: str) -> dict[str, str]:
    values = {
        "kule-schema": "1",
        "kule-profile": PROFILE,
        "kule-required-keys": "token",
        "kule-provider-scope": "github:yesvus/developer",
        "kule-consumer": CONSUMER,
        "kule-expires-at": "2999-12-31",
    }
    values.update(overrides)
    return values


async def test_prepare_is_idempotent_for_the_same_reservation(config):
    executor = FakeExecutor(metadata(custom=existing_reservation()))

    result = await prepare(executor, config)

    assert result["status"] == "awaiting_value"
    assert result["reservation_written"] is True
    assert len(executor.reserves) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"kule-profile": "infra-github"},
        {"kule-consumer": "yesvus-operator"},
        {"kule-required-keys": "token,username"},
        {"kule-provider-scope": "github:yesvus/operator"},
        {"kule-expires-at": "2998-12-31"},
    ],
)
async def test_prepare_refuses_a_different_existing_reservation(config, overrides):
    executor = FakeExecutor(metadata(custom=existing_reservation(**overrides)))

    with pytest.raises(openbao.OpenBaoInputError, match="different Kule metadata reservation"):
        await prepare(executor, config)

    assert executor.reserves == []


async def test_prepare_reports_a_concurrent_version_as_unverified(config):
    class ConcurrentExecutor(FakeExecutor):
        async def reserve_kv_metadata(self, *, mount, path, custom_metadata):
            await super().reserve_kv_metadata(
                mount=mount, path=path, custom_metadata=custom_metadata
            )
            self.current = metadata(version=1, custom=dict(custom_metadata))

    executor = ConcurrentExecutor()

    result = await prepare(executor, config)

    assert result["status"] == "value_present_unverified"
    assert result["reservation_written"] is True


async def test_prepare_reports_unreadable_metadata_after_write(config):
    class LostReadExecutor(FakeExecutor):
        def __init__(self):
            super().__init__()
            self.read_count = 0

        async def read_kv_metadata(self, *, mount, path):
            self.read_count += 1
            return None if self.read_count == 2 else metadata()

    with pytest.raises(openbao.OpenBaoExecutorError, match="cannot read it back"):
        await prepare(LostReadExecutor(), config)


@pytest.mark.parametrize(
    "bad_path",
    [
        "",
        "/tezgah/github/x",
        "tezgah/github/x/",
        "tezgah//github/x",
        "tezgah/../github/x",
        "tezgah/github/../x",
        "tezgah/github/UPPER",
        "tezgah/github/*",
        "other/github/x",
        "tezgah/github",
        "tezgah/github/" + "a" * 200,
    ],
)
async def test_prepare_rejects_paths_outside_the_exact_profile_prefix(config, bad_path):
    executor = FakeExecutor()
    with pytest.raises(openbao.OpenBaoInputError):
        await prepare(executor, config, path=bad_path)
    assert executor.reads == []
    assert executor.reserves == []


@pytest.mark.parametrize(
    "keys",
    [
        [],
        ["token", "token"],
        ["token", "extra"],
        ["1token"],
        ["token", "bad key"],
        ["token", ""],
        ["token", "a" * 65],
        [f"k{index}" for index in range(17)],
    ],
)
async def test_prepare_rejects_keys_outside_the_profile_template(config, keys):
    executor = FakeExecutor()
    with pytest.raises(openbao.OpenBaoInputError):
        await prepare(executor, config, required_keys=keys)
    assert executor.reserves == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"profile": "unknown"},
        {"consumer": "yesvus-operator"},
        {"provider_scope": "github:*"},
        {"provider_scope": "../github"},
        {"provider_scope": "github//owner"},
        {"provider_scope": "github owner"},
        {"provider_scope": "github?\nowner"},
        {"expires_at": "2000-01-01"},
        {"expires_at": "2999-13-01"},
        {"expires_at": "2999-12-31T00:00:00Z"},
    ],
)
async def test_prepare_rejects_unapproved_or_malformed_scope(config, overrides):
    executor = FakeExecutor()
    with pytest.raises((openbao.OpenBaoInputError, openbao.OpenBaoConfigError)):
        await prepare(executor, config, **overrides)
    assert executor.reads == []
    assert executor.reserves == []


async def test_prepare_accepts_free_form_keys_when_profile_has_no_template(config):
    executor = FakeExecutor()
    result = await prepare(
        executor,
        config,
        profile="infra-github",
        path="infra/github/yesvus-operator",
        required_keys=["token", "username"],
        consumer="yesvus-operator",
        provider_scope="github:yesvus/operator",
    )
    assert result["status"] == "awaiting_value"
    assert result["required_keys"] == ["token", "username"]


async def test_status_is_absent_without_metadata(config):
    executor = FakeExecutor()

    result = await openbao.read_status(executor, config, profile=PROFILE, path=PATH)

    assert result["status"] == "absent"
    assert result["value_state"] == "absent"
    assert result["metadata"] is None
    assert result["reservation"] is None
    assert result["reservation_written"] is False
    assert "No KVv2 metadata reservation" in " ".join(result["instructions"])


async def test_status_distinguishes_metadata_only_and_present_value(config):
    reservation = {
        "kule-schema": "1",
        "kule-profile": PROFILE,
        "kule-required-keys": "token",
        "kule-provider-scope": "github:yesvus/developer",
        "kule-consumer": CONSUMER,
        "kule-expires-at": "2000-01-01",
    }
    executor = FakeExecutor(metadata(custom=reservation))

    waiting = await openbao.read_status(executor, config, profile=PROFILE, path=PATH)
    assert waiting["status"] == "awaiting_value"
    assert waiting["reservation_matches_profile"] is True
    assert waiting["expired"] is True
    assert waiting["value_read"] is False

    executor.current = metadata(version=2, custom=reservation)
    present = await openbao.read_status(executor, config, profile=PROFILE, path=PATH)
    assert present["status"] == "value_present_unverified"
    assert present["value_state"] == "value_present_unverified"
    assert present["verification"] == "not_performed"
    assert "Do not replace an existing value" in " ".join(present["instructions"])

    executor.current = metadata(custom={"owner": "team"})
    metadata_only = await openbao.read_status(executor, config, profile=PROFILE, path=PATH)
    assert metadata_only["status"] == "metadata_only"
    assert metadata_only["reservation"] is None
    assert "no recognized Kule reservation" in " ".join(metadata_only["instructions"])


async def test_status_never_echoes_unrecognized_custom_metadata(config):
    executor = FakeExecutor(
        metadata(
            custom={
                "owner": "team",
                "password": "should-not-leak",
                "kule-schema": "1",
                "kule-profile": PROFILE,
                "kule-required-keys": "token",
                "kule-provider-scope": "github:yesvus/developer",
                "kule-consumer": CONSUMER,
            }
        )
    )

    result = await openbao.read_status(executor, config, profile=PROFILE, path=PATH)

    rendered = json.dumps(result)
    assert "should-not-leak" not in rendered
    assert "team" not in rendered
    assert result["metadata"]["custom_metadata_key_count"] == 7
    assert result["metadata"]["recognized_metadata_keys"] == [
        "kule-consumer",
        "kule-profile",
        "kule-provider-scope",
        "kule-required-keys",
        "kule-schema",
    ]


async def test_status_accepts_the_native_metadata_envelope(config):
    executor = FakeExecutor({"data": metadata(custom={"kule-schema": "1"})})

    result = await openbao.read_status(executor, config, profile=PROFILE, path=PATH)

    assert result["status"] == "metadata_only"
    assert result["metadata"]["current_version"] == 0


@pytest.mark.parametrize(
    "bad",
    [
        "not a mapping",
        {"current_version": True},
        {"current_version": -1},
        {"current_version": 0, "custom_metadata": {"key": 1}},
        {"current_version": 0, "custom_metadata": "not a mapping"},
        {"current_version": 0, "cas_required": "yes"},
        {"current_version": 0, "max_versions": -1},
        {"current_version": 0, "created_time": 5},
        {"current_version": 0, "created_time": "line\nbreak"},
    ],
)
async def test_status_rejects_invalid_executor_metadata(config, bad):
    executor = FakeExecutor(bad)
    with pytest.raises(openbao.OpenBaoExecutorError):
        await openbao.read_status(executor, config, profile=PROFILE, path=PATH)


def test_config_rejects_a_guessed_or_insecure_ui_template():
    base = dict(
        profiles=(
            openbao.OpenBaoProfile(
                name=PROFILE,
                path_prefix="tezgah/github",
                consumers=(CONSUMER,),
            ),
        )
    )
    for template in (
        "",
        "http://bao.example.com/ui/vault/secrets/{mount}/show/{path}",
        "https://bao.example.com/ui/{mount}",
        "https://bao.example.com/ui/{path}",
        "https://user:pass@bao.example.com/ui/{mount}/{path}",
        "https://bao.example.com/ui/{mount}/{path}?x=1",
        "https://bao.example.com/ui/{mount}/{path}#fragment",
        "https://bao.example.com/ui/{mount}/{unknown}",
    ):
        with pytest.raises(openbao.OpenBaoConfigError):
            openbao.OpenBaoConfig(ui_secret_url_template=template, **base)


def test_profiles_reject_broad_or_unsafe_targets():
    with pytest.raises(openbao.OpenBaoConfigError):
        openbao.OpenBaoProfile(name="p", path_prefix="../any", consumers=("consumer",))
    with pytest.raises(openbao.OpenBaoConfigError):
        openbao.OpenBaoProfile(name="p", path_prefix="any/*", consumers=("consumer",))
    with pytest.raises(openbao.OpenBaoConfigError):
        openbao.OpenBaoProfile(name="p", path_prefix="any", consumers=())
    with pytest.raises(openbao.OpenBaoConfigError):
        openbao.OpenBaoProfile(name="p", path_prefix="any", consumers=("C",))
    with pytest.raises(openbao.OpenBaoConfigError):
        openbao.OpenBaoProfile(name="p", path_prefix="any", consumers="consumer")
    with pytest.raises(openbao.OpenBaoConfigError):
        openbao.OpenBaoProfile(
            name="p",
            path_prefix="any",
            consumers=("consumer",),
            required_keys=("bad key",),
        )
    with pytest.raises(openbao.OpenBaoConfigError):
        openbao.OpenBaoProfile(
            name="p",
            path_prefix="any",
            consumers=("consumer",),
            required_keys=tuple(f"k{index}" for index in range(17)),
        )
    with pytest.raises(openbao.OpenBaoConfigError):
        openbao.OpenBaoConfig(
            profiles=("not a profile",),
            ui_secret_url_template="https://bao.example.com/{mount}/{path}",
        )
    with pytest.raises(openbao.OpenBaoConfigError):
        openbao.OpenBaoConfig(
            profiles=(
                openbao.OpenBaoProfile(name="profile", path_prefix="any", consumers=("consumer",)),
            ),
            ui_secret_url_template="https://bao.example.com/{mount}/{path}",
            max_required_keys=17,
        )


def test_executor_contract_is_metadata_only():
    names = {name for name in dir(openbao.OpenBaoExecutor) if not name.startswith("_")}
    assert names == {"read_kv_metadata", "reserve_kv_metadata"}


def test_request_and_result_surface_has_no_secret_or_acl_fields():
    assert {field.name for field in fields(openbao.OnboardingRequest)} == {
        "profile",
        "path",
        "required_keys",
        "provider_scope",
        "consumer",
        "expires_at",
    }
    assert set(openbao.SUPPORTED_ACTIONS) == {"metadata_reserve", "metadata_status"}
    assert set(openbao.UNSUPPORTED_ACTIONS) == {
        "issue",
        "deliver",
        "rotate",
        "revoke",
        "policy_authoring",
        "role_authoring",
        "secret_read",
        "secret_write",
    }


def test_supported_and_unsupported_actions_are_explicit(config):
    assert openbao.SUPPORTED_ACTIONS == ("metadata_reserve", "metadata_status")
    for action, reason in openbao.UNSUPPORTED_ACTIONS.items():
        assert action
        assert "not implemented" in reason.lower() or "not accepted" in reason.lower()
    assert "credential_*" in openbao.UNSUPPORTED_ACTIONS["issue"]
    assert "#725/#1030" in openbao.UNSUPPORTED_ACTIONS["deliver"]


async def test_tool_surface_is_operator_only_and_has_no_secret_inputs(config):
    executor = FakeExecutor()
    mcp = FastMCP(name="openbao-test")
    openbao.register(mcp, executor=executor, config=config)

    async with Client(mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}

    assert set(tools) == {"openbao_onboarding_prepare", "openbao_status"}
    for tool in tools.values():
        assert tool.meta["fastmcp"]["tags"] == ["operate"]
    assert tools["openbao_onboarding_prepare"].annotations.read_only_hint is False
    assert tools["openbao_status"].annotations.read_only_hint is True

    write = await mcp.get_tool("openbao_onboarding_prepare")
    status = await mcp.get_tool("openbao_status")
    assert write is not None
    assert status is not None
    write_props = set(write.parameters["properties"])
    assert write_props == {
        "profile",
        "path",
        "required_keys",
        "provider_scope",
        "consumer",
        "expires_at",
    }
    read_props = set(status.parameters["properties"])
    assert read_props == {"profile", "path"}
    forbidden = ("secret", "token", "value", "policy", "acl", "master", "password")
    assert not any(word in prop.lower() for prop in write_props for word in forbidden)


async def test_shared_middleware_hides_and_denies_developer_identity(make_cfg, claims, config):
    cfg = make_cfg(workspace_enabled=True, developer_enabled=True)
    policy = Policy(
        required_group="ops",
        exec_group="ops-exec",
        exec_enabled=False,
        workspace_enabled=True,
        developer_enabled=True,
    )
    middleware = OperatorMiddleware(
        policy=policy,
        audit=AuditLog(cfg.audit.path),
        kill_switch=cfg.kill_switch_path,
        timeout_seconds=cfg.tools.timeout_seconds,
        claims_getter=claims,
    )
    executor = FakeExecutor()
    mcp = FastMCP(name="openbao-test", middleware=[middleware])
    openbao.register(mcp, executor=executor, config=config)

    claims.value = {"sub": "dev", "groups": ["mcp-developers", "mcp-workspace"]}
    async with Client(mcp) as client:
        assert await client.list_tools() == []
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("openbao_status", {"profile": PROFILE, "path": PATH})

    claims.value = {"sub": "owner", "groups": ["ops"]}
    async with Client(mcp) as client:
        names = {tool.name for tool in await client.list_tools()}
        assert names == {"openbao_onboarding_prepare", "openbao_status"}
        result = await client.call_tool(
            "openbao_onboarding_prepare",
            {
                "profile": PROFILE,
                "path": PATH,
                "required_keys": ["token"],
                "provider_scope": "github:yesvus/developer",
                "consumer": CONSUMER,
                "expires_at": "2999-12-31",
            },
        )
    assert result.data["status"] == "awaiting_value"
    assert executor.reserves
    audit = cfg.audit.path.read_text()
    assert '"event": "denied"' in audit
    assert '"event": "result"' in audit
