"""Tests for HostRegistry, HostTransport contract, per-host RBAC, and target-aware audit."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from types import MappingProxyType

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from kule.audit import AuditLog, verify
from kule.authz import EXEC, HOST_SCOPED, OPERATE, READ, WORKSPACE, HostOperation, Policy
from kule.config import ConfigError, load_config
from kule.hosts import (
    HostConfig,
    HostPlatform,
    HostPolicy,
    HostRegistry,
    HostTransportType,
    SshTargetConfig,
)
from kule.integrations import (
    Capability,
    Integration,
    IntegrationRegistry,
    capability_tag,
    integration_tag,
)
from kule.redact import MASK
from kule.server import build_server
from kule.transport import (
    ExecResult,
    HostKeyVerificationError,
    HostStatus,
    HostTransport,
    HostUnreachableError,
    TransportConfigError,
    TransportError,
)

BASE_TOML = """
[server]
public_url = "https://mcp.example.com"
[auth]
oidc_config_url = "https://id.example.com/.well-known/openid-configuration"
client_id = "c"
"""

ENV = {"KULE_OIDC_CLIENT_SECRET": "s", "KULE_JWT_SIGNING_KEY": "k" * 32}


def _host(
    host_id: str = "alpha",
    *,
    platform: HostPlatform = HostPlatform.LINUX,
    address: str = "192.0.2.10",
    user: str = "operator",
    port: int = 22,
    read_groups: frozenset[str] = frozenset({"ops-alpha"}),
    exec_groups: frozenset[str] = frozenset({"exec-alpha"}),
    exec_enabled: bool = False,
    description: str = "",
) -> HostConfig:
    return HostConfig(
        host_id=host_id,
        transport=HostTransportType.SSH,
        platform=platform,
        ssh=SshTargetConfig(
            host=address,
            user=user,
            key_path=Path("/var/run/kule/id_ed25519"),
            known_hosts_path=Path("/var/run/kule/known_hosts"),
            port=port,
        ),
        policy=HostPolicy(
            read_groups=read_groups,
            exec_groups=exec_groups,
            exec_enabled=exec_enabled,
        ),
        description=description,
    )


# --- HostRegistry & inventory validation ------------------------------------


def test_host_registry_valid_hosts_and_public_metadata():
    linux = _host("linux-1", platform=HostPlatform.LINUX, address="srv1.example.com", port=2222)
    macos = _host("zombie", platform=HostPlatform.MACOS, address="2001:db8::5", description="Mac")
    reg = HostRegistry([linux, macos])

    assert len(reg) == 2
    assert bool(reg) is True
    assert "linux-1" in reg and "zombie" in reg and "unknown" not in reg
    assert reg.host_ids() == ("linux-1", "zombie")
    assert reg.get("linux-1") == linux
    assert reg.require("zombie") == macos
    assert reg.get("missing") is None
    with pytest.raises(KeyError):
        reg.require("missing")

    # key_path is excluded from repr and public_metadata leaks no SSH internals.
    assert "id_ed25519" not in repr(linux.ssh)
    meta = macos.public_metadata()
    assert meta == {
        "host_id": "zombie",
        "transport": "ssh",
        "platform": "macos",
        "exec_enabled": False,
        "description": "Mac",
    }
    assert not any(k in meta for k in ("key_path", "known_hosts_path", "user", "host", "port"))


def test_host_registry_rejects_duplicate_host_id():
    with pytest.raises(ValueError, match="duplicate host_id"):
        HostRegistry([_host("dup"), _host("dup", address="192.0.2.11")])


@pytest.mark.parametrize(
    "bad_id",
    ["", "Upper", "a/b", "a..b", "-lead", "host*", "host?", "a b", "x" * 65],
)
def test_host_config_rejects_invalid_host_id(bad_id):
    with pytest.raises(ValueError, match="host_id"):
        _host(bad_id)


@pytest.mark.parametrize(
    "bad_addr",
    [
        "",
        " ",
        "*",
        "*.example.com",
        "host?.example.com",
        "10.0.0.0/24",
        "0.0.0.0",
        "::",
        "operator@host.example.com",
        "ssh://host.example.com",
        "-oProxyCommand=id",
        "host.example.com:22",
        "host name",
        "host\nname",
    ],
)
def test_ssh_target_rejects_wildcard_and_arbitrary_addresses(bad_addr):
    with pytest.raises(ValueError, match="ssh.host"):
        _host(address=bad_addr)


@pytest.mark.parametrize("bad_user", ["", "-o", "a@b", "user*", "bad user", "1user"])
def test_ssh_target_rejects_invalid_username(bad_user):
    with pytest.raises(ValueError, match="ssh.user"):
        _host(user=bad_user)


@pytest.mark.parametrize("bad_port", [0, -1, 65536, True, "22"])
def test_ssh_target_rejects_invalid_port(bad_port):
    with pytest.raises(ValueError, match="ssh.port"):
        _host(port=bad_port)


def test_ssh_target_rejects_wildcard_or_empty_paths():
    with pytest.raises(ValueError, match="key_path"):
        SshTargetConfig(
            host="192.0.2.10",
            user="operator",
            key_path=Path("/keys/*"),
            known_hosts_path=Path("/keys/known_hosts"),
        )
    with pytest.raises(ValueError, match="known_hosts_path"):
        SshTargetConfig(
            host="192.0.2.10",
            user="operator",
            key_path=Path("/keys/id"),
            known_hosts_path=Path(" "),
        )


@pytest.mark.parametrize(
    "bad_groups",
    [frozenset({""}), frozenset({"*"}), frozenset({"ops*"}), frozenset({" ops"}), ["ops"]],
)
def test_host_policy_rejects_malformed_groups(bad_groups):
    with pytest.raises(ValueError, match="read_groups"):
        HostPolicy(read_groups=bad_groups)  # type: ignore[arg-type]


def test_host_policy_defaults_exec_disabled_and_rejects_non_bool():
    p = HostPolicy()
    assert p.exec_enabled is False
    assert p.read_groups == frozenset()
    assert p.exec_groups == frozenset()
    with pytest.raises(ValueError, match="exec_enabled"):
        HostPolicy(exec_enabled="true")  # type: ignore[arg-type]


# --- TOML config loading & v0.1.0 backwards compatibility -------------------


def test_v010_config_without_hosts_stays_backwards_compatible(tmp_path: Path):
    cfg_path = tmp_path / "kule.toml"
    cfg_path.write_text(BASE_TOML)
    cfg = load_config(cfg_path, ENV)
    assert cfg.hosts == ()
    assert len(cfg.host_registry()) == 0


def test_config_loads_multi_host_inventory_toml(tmp_path: Path):
    toml = (
        BASE_TOML
        + """
[[hosts]]
host_id = "linux-box"
transport = "ssh"
platform = "linux"
description = "Primary Linux node"
[hosts.ssh]
host = "192.0.2.10"
user = "operator"
port = 2222
key_path = "/var/run/kule/linux_ed25519"
known_hosts_path = "/var/run/kule/known_hosts"
[hosts.policy]
read_groups = ["ops", "linux-readers"]
exec_groups = ["ops-exec"]
exec_enabled = false

[[hosts]]
host_id = "zombie"
platform = "macos"
[hosts.ssh]
host = "zombie.lan"
user = "admin"
key_path = "/var/run/kule/zombie_ed25519"
known_hosts_path = "/var/run/kule/known_hosts"
[hosts.policy]
read_groups = ["ops"]
"""
    )
    cfg_path = tmp_path / "kule.toml"
    cfg_path.write_text(toml)
    cfg = load_config(cfg_path, ENV)
    reg = cfg.host_registry()
    assert reg.host_ids() == ("linux-box", "zombie")
    linux = reg.require("linux-box")
    assert linux.platform is HostPlatform.LINUX
    assert linux.ssh.port == 2222
    assert linux.policy.read_groups == frozenset({"ops", "linux-readers"})
    assert linux.policy.exec_enabled is False
    zombie = reg.require("zombie")
    assert zombie.transport is HostTransportType.SSH
    assert zombie.platform is HostPlatform.MACOS
    assert zombie.ssh.port == 22
    assert zombie.policy.exec_enabled is False


@pytest.mark.parametrize(
    ("extra_toml", "match"),
    [
        (
            """
[[hosts]]
host_id = "a"
platform = "linux"
[hosts.ssh]
host = "192.0.2.10"
user = "op"
key_path = "/k"
known_hosts_path = "/kh"
[[hosts]]
host_id = "a"
platform = "macos"
[hosts.ssh]
host = "192.0.2.11"
user = "op"
key_path = "/k"
known_hosts_path = "/kh"
""",
            "duplicate host_id",
        ),
        (
            """
[[hosts]]
host_id = "a"
platform = "linux"
[hosts.ssh]
host = "*.example.com"
user = "op"
key_path = "/k"
known_hosts_path = "/kh"
""",
            "ssh.host",
        ),
        (
            """
[[hosts]]
host_id = "a"
transport = "telnet"
platform = "linux"
[hosts.ssh]
host = "192.0.2.10"
user = "op"
key_path = "/k"
known_hosts_path = "/kh"
""",
            "transport",
        ),
        (
            """
[[hosts]]
host_id = "a"
platform = "windows"
[hosts.ssh]
host = "192.0.2.10"
user = "op"
key_path = "/k"
known_hosts_path = "/kh"
""",
            "platform",
        ),
        (
            """
[[hosts]]
host_id = "a"
platform = "linux"
[hosts.ssh]
host = "192.0.2.10"
user = "op"
key_path = "/k"
known_hosts_path = "/kh"
[hosts.policy]
exec_enable = true
""",
            "unknown setting",
        ),
    ],
)
def test_config_rejects_malformed_host_inventory(tmp_path: Path, extra_toml: str, match: str):
    cfg_path = tmp_path / "kule.toml"
    cfg_path.write_text(BASE_TOML + extra_toml)
    with pytest.raises(ConfigError, match=match):
        load_config(cfg_path, ENV)


# --- HostTransport protocol & result types ----------------------------------


class _DummyTransport:
    @property
    def transport_name(self) -> str:
        return "ssh"

    async def status(self, host: HostConfig, *, timeout_seconds: float) -> HostStatus:
        return HostStatus(
            host_id=host.host_id,
            transport=self.transport_name,
            platform=host.platform,
            reachable=True,
            latency_ms=12,
            os_info="Darwin arm64",
        )

    async def read_command(
        self,
        host: HostConfig,
        command: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ExecResult:
        return ExecResult(
            host_id=host.host_id,
            transport=self.transport_name,
            returncode=0,
            output="ok",
            duration_ms=5,
        )

    async def exec_script(
        self,
        host: HostConfig,
        script: str,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ExecResult:
        return ExecResult(
            host_id=host.host_id,
            transport=self.transport_name,
            returncode=None,
            output="",
            timed_out=True,
            duration_ms=int(timeout_seconds * 1000),
            error="timed out",
        )


def test_host_transport_protocol_and_error_hierarchy():
    assert isinstance(_DummyTransport(), HostTransport)
    assert not isinstance(object(), HostTransport)
    assert issubclass(HostUnreachableError, TransportError)
    assert issubclass(HostKeyVerificationError, TransportError)
    assert issubclass(TransportConfigError, TransportError)
    assert issubclass(TransportError, RuntimeError)


# --- Per-host authorization (caller x host_id x operation) ------------------


def test_per_host_authz_read_and_exec_fail_closed():
    host_a = _host(
        "host-a",
        read_groups=frozenset({"read-a"}),
        exec_groups=frozenset({"exec-a"}),
        exec_enabled=True,
    )
    host_b = _host(
        "host-b",
        read_groups=frozenset({"read-b"}),
        exec_groups=frozenset({"exec-b"}),
        exec_enabled=False,
    )
    host_empty = _host("host-empty", read_groups=frozenset(), exec_groups=frozenset())
    reg = HostRegistry([host_a, host_b, host_empty])

    policy = Policy(required_group="ops", exec_group="ops-exec", exec_enabled=True)
    caller_a = policy.caller_from_claims({"sub": "u1", "groups": ["ops", "read-a", "exec-a"]})
    caller_b = policy.caller_from_claims({"sub": "u2", "groups": ["ops", "read-b", "exec-b"]})

    # Fail-closed on unauthenticated, missing registry, unknown host, unknown op.
    assert policy.allows_host(None, reg, "host-a", HostOperation.READ)[0] is False
    assert policy.allows_host(caller_a, None, "host-a", HostOperation.READ)[0] is False
    assert policy.allows_host(caller_a, reg, "", HostOperation.READ)[0] is False
    assert policy.allows_host(caller_a, reg, "missing", HostOperation.READ)[0] is False
    assert policy.allows_host(caller_a, reg, "host-a", "write")[0] is False
    assert policy.allows_host(caller_a, reg, "host-empty", HostOperation.READ)[0] is False

    # Read isolation: host-a != host-b.
    assert policy.allows_host(caller_a, reg, "host-a", HostOperation.READ) == (True, "ok")
    assert policy.allows_host(caller_a, reg, "host-b", HostOperation.READ)[0] is False
    assert policy.allows_host(caller_b, reg, "host-b", HostOperation.READ) == (True, "ok")
    assert policy.allows_host(caller_b, reg, "host-a", HostOperation.READ)[0] is False

    # Exec isolation: enabled on host-a does not permit host-b, and disabled host fails closed.
    assert policy.allows_host(caller_a, reg, "host-a", HostOperation.EXEC) == (True, "ok")
    assert policy.allows_host(caller_a, reg, "host-b", HostOperation.EXEC)[0] is False
    assert policy.allows_host(caller_b, reg, "host-b", HostOperation.EXEC)[0] is False

    # Global exec_enabled=False overrides per-host exec_enabled=True.
    policy_exec_off = Policy(required_group="ops", exec_group="ops-exec", exec_enabled=False)
    assert policy_exec_off.allows_host(caller_a, reg, "host-a", HostOperation.EXEC) == (
        False,
        "exec tier is disabled",
    )

    # authorized_hosts never leaks unauthorized hosts.
    assert [h.host_id for h in policy.authorized_hosts(caller_a, reg, HostOperation.READ)] == [
        "host-a"
    ]
    assert [h.host_id for h in policy.authorized_hosts(caller_a, reg, HostOperation.EXEC)] == [
        "host-a"
    ]
    assert [h.host_id for h in policy.authorized_hosts(caller_b, reg, HostOperation.EXEC)] == []
    assert policy.authorized_hosts(None, reg, HostOperation.READ) == ()


# --- Target-aware audit & middleware integration ----------------------------


def test_audit_log_target_fields_redaction_and_verify(tmp_path: Path):
    audit_path = tmp_path / "audit.jsonl"
    log = AuditLog(audit_path)
    secret = "ghp_" + "z" * 36

    # v0.1.0 call without target fields omits them.
    log.write("call", tool="whoami")
    # v0.2.0 target-aware call includes host_id, transport, request_id, grant_id.
    log.write(
        "call",
        host_id="zombie",
        transport="ssh",
        request_id="req-1234",
        grant_id="bg-42",
        tool="host_exec",
        note=f"token={secret}",
    )

    assert verify(audit_path) == (True, 2)
    lines = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert "host_id" not in lines[0]
    assert "grant_id" not in lines[0]
    assert lines[1]["host_id"] == "zombie"
    assert lines[1]["transport"] == "ssh"
    assert lines[1]["request_id"] == "req-1234"
    assert lines[1]["grant_id"] == "bg-42"
    assert secret not in audit_path.read_text()
    assert MASK in lines[1]["note"]


async def test_middleware_enforces_host_scoped_authz_and_target_audit(make_cfg, claims):
    host_a = _host(
        "host-a",
        read_groups=frozenset({"read-a"}),
        exec_groups=frozenset({"exec-a"}),
        exec_enabled=True,
    )
    host_b = _host(
        "host-b",
        read_groups=frozenset({"read-b"}),
        exec_groups=frozenset({"exec-b"}),
        exec_enabled=False,
    )
    base_cfg = make_cfg(exec_enabled=True)
    cfg = type(base_cfg)(
        server=base_cfg.server,
        auth=base_cfg.auth,
        audit=base_cfg.audit,
        tools=base_cfg.tools,
        hosts=(host_a, host_b),
    )
    mcp = build_server(cfg, claims_getter=claims)

    executed: list[tuple[str, str]] = []

    @mcp.tool(tags={READ, HOST_SCOPED})
    async def host_status(host_id: str) -> dict:
        executed.append(("status", host_id))
        return {"host_id": host_id, "reachable": True}

    @mcp.tool(tags={EXEC, HOST_SCOPED})
    async def host_exec(host_id: str, script: str) -> dict:
        executed.append(("exec", host_id))
        return {"host_id": host_id, "returncode": 0}

    # Caller with only ops (no per-host read/exec groups) cannot see host-scoped tools.
    claims.value = {"sub": "u0", "preferred_username": "plain", "groups": ["ops"]}
    async with Client(mcp) as client:
        names = {t.name for t in await client.list_tools()}
        assert "host_status" not in names and "host_exec" not in names

    # Caller authorized for host-a read+exec with a grant_id.
    claims.value = {
        "sub": "u1",
        "preferred_username": "alice",
        "groups": ["ops", "ops-exec", "read-a", "exec-a"],
        "breakglass_grant_id": "grant-99",
    }
    async with Client(mcp) as client:
        names = {t.name for t in await client.list_tools()}
        assert {"host_status", "host_exec"} <= names

        res = await client.call_tool("host_status", {"host_id": "host-a"})
        assert res.data == {"host_id": "host-a", "reachable": True}

        # Wrong host denied fail-closed without leaking policy.
        with pytest.raises(ToolError) as exc:
            await client.call_tool("host_status", {"host_id": "host-b"})
        assert "read-b" not in str(exc.value)

        # Unknown host denied fail-closed.
        with pytest.raises(ToolError):
            await client.call_tool("host_status", {"host_id": "no-such-host"})

        # Exec on host-b (disabled & wrong host) denied, raw script not logged.
        with pytest.raises(ToolError):
            await client.call_tool("host_exec", {"host_id": "host-b", "script": "echo secret-body"})

        # Exec on host-a succeeds.
        res_exec = await client.call_tool("host_exec", {"host_id": "host-a", "script": "uname -a"})
        assert res_exec.data == {"host_id": "host-a", "returncode": 0}

    assert executed == [("status", "host-a"), ("exec", "host-a")]
    raw_audit = cfg.audit.path.read_text()
    assert "secret-body" not in raw_audit
    events = [json.loads(line) for line in raw_audit.splitlines()]
    assert verify(cfg.audit.path) == (True, len(events))

    # Every event has request_id and grant_id from caller claims.
    assert all(e.get("request_id") for e in events)
    assert all(e.get("grant_id") == "grant-99" for e in events)

    # Check host_id and transport annotations on allowed & denied calls.
    status_call = next(e for e in events if e["event"] == "call" and e["tool"] == "host_status")
    assert status_call["host_id"] == "host-a"
    assert status_call["transport"] == "ssh"

    denied_b = next(
        e
        for e in events
        if e["event"] == "denied" and e["tool"] == "host_status" and e.get("host_id") == "host-b"
    )
    assert denied_b["transport"] == "ssh"

    denied_unknown = next(
        e for e in events if e["event"] == "denied" and e.get("host_id") == "no-such-host"
    )
    assert "transport" not in denied_unknown

    # Kill switch blocks even authorized host-a call and preserves target audit fields.
    cfg.kill_switch_path.touch()
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="kill switch"):
            await client.call_tool("host_status", {"host_id": "host-a"})
    last = json.loads(cfg.audit.path.read_text().splitlines()[-1])
    assert last["event"] == "denied"
    assert last["reason"] == "kill switch"
    assert last["host_id"] == "host-a"
    assert last["transport"] == "ssh"
    assert last["request_id"]
    assert verify(cfg.audit.path)[0] is True


# --- Review finding regression tests ----------------------------------------


def test_host_registry_internal_mapping_is_immutable():
    reg = HostRegistry([_host("alpha")])
    assert isinstance(reg._hosts, MappingProxyType)
    with pytest.raises(TypeError):
        reg._hosts["beta"] = _host("beta")  # type: ignore[index]


@pytest.mark.parametrize(
    "bad_addr",
    [
        "fe80::1%eth0",
        "fe80::1%25",
        "::ffff:0.0.0.0",
        "::ffff:0:0",
    ],
)
def test_ssh_target_rejects_scoped_and_ipv4_mapped_unspecified_ipv6(bad_addr):
    with pytest.raises(ValueError, match="ssh.host"):
        _host(address=bad_addr)


@pytest.mark.parametrize("ctrl", ["\x00", "\x07", "\t", "\n", "\r", "\x1b", "\x7f"])
def test_hosts_reject_all_ascii_control_chars(ctrl):
    with pytest.raises(ValueError, match="description"):
        _host(description=f"node{ctrl}1")
    with pytest.raises(ValueError, match="key_path"):
        SshTargetConfig(
            host="192.0.2.10",
            user="operator",
            key_path=Path(f"/keys/id{ctrl}1"),
            known_hosts_path=Path("/keys/known_hosts"),
        )
    with pytest.raises(ValueError, match="known_hosts_path"):
        SshTargetConfig(
            host="192.0.2.10",
            user="operator",
            key_path=Path("/keys/id"),
            known_hosts_path=Path(f"/keys/kh{ctrl}1"),
        )
    with pytest.raises(ValueError, match="read_groups"):
        HostPolicy(read_groups=frozenset({f"ops{ctrl}1"}))
    with pytest.raises(ValueError, match="exec_groups"):
        HostPolicy(exec_groups=frozenset({f"exec{ctrl}1"}))


def test_config_rejects_exec_enabled_with_empty_exec_groups(tmp_path: Path):
    toml = (
        BASE_TOML
        + """
[[hosts]]
host_id = "a"
platform = "linux"
[hosts.ssh]
host = "192.0.2.10"
user = "op"
key_path = "/k"
known_hosts_path = "/kh"
[hosts.policy]
read_groups = ["ops"]
exec_enabled = true
exec_groups = []
"""
    )
    cfg_path = tmp_path / "kule.toml"
    cfg_path.write_text(toml)
    with pytest.raises(ConfigError, match="exec_groups"):
        load_config(cfg_path, ENV)


@pytest.mark.parametrize(
    "bad_grant",
    ["", "   ", "g\x1b[31m", "g\x7fid", "g\x07id", "g\nid", "x" * 129],
)
def test_caller_from_claims_rejects_non_printable_grant_id(bad_grant):
    policy = Policy(required_group="ops", exec_group="ops-exec", exec_enabled=True)
    caller = policy.caller_from_claims(
        {"sub": "u1", "groups": ["ops"], "breakglass_grant_id": bad_grant}
    )
    assert caller is not None
    assert caller.grant_id is None


async def test_middleware_ignores_caller_supplied_grant_id_and_digests_custom_host_exec(
    make_cfg, claims
):
    host_a = _host(
        "host-a",
        read_groups=frozenset({"read-a"}),
        exec_groups=frozenset({"exec-a"}),
        exec_enabled=True,
    )
    base_cfg = make_cfg(exec_enabled=True)
    cfg = type(base_cfg)(
        server=base_cfg.server,
        auth=base_cfg.auth,
        audit=base_cfg.audit,
        tools=base_cfg.tools,
        hosts=(host_a,),
    )
    mcp = build_server(cfg, claims_getter=claims)

    @mcp.tool(tags={EXEC, HOST_SCOPED})
    async def custom_host_run(host_id: str, script: str, grant_id: str = "") -> dict:
        return {"host_id": host_id, "ok": True}

    claims.value = {
        "sub": "u1",
        "preferred_username": "alice",
        "groups": ["ops", "ops-exec", "read-a", "exec-a"],
    }
    async with Client(mcp) as client:
        res = await client.call_tool(
            "custom_host_run",
            {"host_id": "host-a", "script": "echo top-secret-script", "grant_id": "spoofed-99"},
        )
        assert res.data == {"host_id": "host-a", "ok": True}

    raw_audit = cfg.audit.path.read_text()
    assert "top-secret-script" not in raw_audit
    events = [json.loads(line) for line in raw_audit.splitlines()]
    assert all("grant_id" not in e for e in events)
    call_event = next(e for e in events if e["event"] == "call")
    assert call_event["args"]["script_valid"] is True
    assert isinstance(call_event["args"]["script_sha256"], str)
    assert call_event["args"]["host_id"] == "host-a"


async def test_middleware_denies_unsupported_tiers_and_integration_tags_on_host_scoped(
    make_cfg, claims
):
    host_a = _host(
        "host-a",
        read_groups=frozenset({"read-a"}),
        exec_groups=frozenset({"exec-a"}),
        exec_enabled=True,
    )
    base_cfg = make_cfg(exec_enabled=True)
    cfg = type(base_cfg)(
        server=base_cfg.server,
        auth=base_cfg.auth,
        audit=base_cfg.audit,
        tools=base_cfg.tools,
        hosts=(host_a,),
    )
    integrations = IntegrationRegistry()
    integrations.register(
        Integration(
            name="k8s",
            enabled=True,
            backend_identity="cluster-1",
            capabilities=frozenset({Capability.K8S_READ}),
            targets={"host_id": frozenset({"host-a"})},
        )
    )
    mcp = build_server(cfg, claims_getter=claims, integrations=integrations)

    @mcp.tool(tags={OPERATE, HOST_SCOPED})
    async def host_operate(host_id: str) -> dict:
        return {"ok": True}

    @mcp.tool(tags={WORKSPACE, HOST_SCOPED})
    async def host_workspace(host_id: str) -> dict:
        return {"ok": True}

    @mcp.tool(tags={integration_tag("k8s"), capability_tag(Capability.K8S_READ), HOST_SCOPED})
    async def host_k8s_hybrid(host_id: str) -> dict:
        return {"ok": True}

    claims.value = {
        "sub": "u1",
        "preferred_username": "alice",
        "groups": ["ops", "ops-exec", "read-a", "exec-a", "mcp-workspace"],
    }
    async with Client(mcp) as client:
        names = {t.name for t in await client.list_tools()}
        assert "host_operate" not in names
        assert "host_workspace" not in names
        assert "host_k8s_hybrid" not in names

        for tool_name in ("host_operate", "host_workspace", "host_k8s_hybrid"):
            with pytest.raises(ToolError, match="not authorized"):
                await client.call_tool(tool_name, {"host_id": "host-a"})
