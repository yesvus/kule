"""Tests for SshHostTransport, multi-host MCP tools, macOS portability, and audit integrity."""

from __future__ import annotations

import json
import stat
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from helpers import OPERATOR, OUTSIDER

from kule.audit import verify as verify_audit
from kule.hosts import HostConfig, HostPlatform, HostPolicy, HostTransportType, SshTargetConfig
from kule.server import build_server
from kule.ssh_transport import SshHostTransport
from kule.transport import (
    ExecResult,
    HostKeyVerificationError,
    HostStatus,
    HostTransport,
    HostUnreachableError,
    TransportConfigError,
)


def _make_ssh_files(tmp_path: Path, name: str) -> tuple[Path, Path]:
    key = tmp_path / f"{name}_id_ed25519"
    known = tmp_path / f"{name}_known_hosts"
    key.write_text("DUMMY-KEY")
    known.write_text("192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockKey\n")
    return key, known


def _make_host(
    tmp_path: Path,
    host_id: str,
    *,
    platform: HostPlatform = HostPlatform.LINUX,
    host: str = "192.0.2.10",
    user: str = "kule",
    port: int = 22,
    read_groups: frozenset[str] = frozenset({"ops"}),
    exec_groups: frozenset[str] = frozenset({"ops-exec"}),
    exec_enabled: bool = False,
    description: str = "",
) -> HostConfig:
    key, known = _make_ssh_files(tmp_path, host_id)
    return HostConfig(
        host_id=host_id,
        transport=HostTransportType.SSH,
        platform=platform,
        ssh=SshTargetConfig(
            host=host,
            user=user,
            key_path=key,
            known_hosts_path=known,
            port=port,
        ),
        policy=HostPolicy(
            read_groups=read_groups,
            exec_groups=exec_groups,
            exec_enabled=exec_enabled,
        ),
        description=description,
    )


def _make_fake_ssh(tmp_path: Path, body: str) -> str:
    """Create a tiny executable Python script acting as a fake /usr/bin/ssh."""
    script = tmp_path / "fake_ssh.py"
    script.write_text(f"#!{sys.executable}\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def _read_audit(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Unit tests: SshHostTransport contract, hardened argv, macOS portability
# ---------------------------------------------------------------------------


def test_ssh_transport_implements_protocol():
    transport = SshHostTransport()
    assert isinstance(transport, HostTransport)
    assert transport.transport_name == "ssh"


def test_ssh_argv_is_hardened_and_portable(tmp_path: Path):
    host = _make_host(
        tmp_path,
        "zombie",
        platform=HostPlatform.MACOS,
        host="zombie.internal",
        user="operator",
        port=2222,
    )
    transport = SshHostTransport(ssh_bin="/usr/bin/ssh")
    argv = transport.build_argv(host, "/bin/bash --noprofile --norc -s")

    assert argv[0] == "/usr/bin/ssh"
    assert "-F" in argv and argv[argv.index("-F") + 1] == "/dev/null"
    assert "-T" in argv
    assert "-p" in argv and argv[argv.index("-p") + 1] == "2222"
    assert "BatchMode=yes" in argv
    assert "IdentitiesOnly=yes" in argv
    assert "IdentityAgent=none" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert f"UserKnownHostsFile={host.ssh.known_hosts_path}" in argv
    assert "GlobalKnownHostsFile=/dev/null" in argv
    assert "ClearAllForwardings=yes" in argv
    assert "ServerAliveInterval=5" in argv
    assert "ServerAliveCountMax=1" in argv
    assert "-i" in argv and argv[argv.index("-i") + 1] == str(host.ssh.key_path)
    assert argv[-3] == "--"
    assert argv[-2] == "operator@zombie.internal"
    assert argv[-1] == "/bin/bash --noprofile --norc -s"
    assert "/usr/bin/timeout" not in " ".join(argv)


async def test_ssh_missing_prereqs_fail_closed_without_leaking_paths(tmp_path: Path):
    host = _make_host(tmp_path, "gurbet")
    fake_ssh = _make_fake_ssh(tmp_path, "import sys; sys.exit(0)")
    transport = SshHostTransport(ssh_bin=fake_ssh)

    host.ssh.key_path.unlink()
    with pytest.raises(TransportConfigError) as exc_key:
        await transport.status(host, timeout_seconds=5)
    assert str(host.ssh.key_path) not in str(exc_key.value)

    host.ssh.key_path.write_text("RESTORED")
    host.ssh.known_hosts_path.unlink()
    with pytest.raises(TransportConfigError) as exc_kh:
        await transport.status(host, timeout_seconds=5)
    assert str(host.ssh.known_hosts_path) not in str(exc_kh.value)

    missing_bin = SshHostTransport(ssh_bin=str(tmp_path / "does-not-exist-ssh"))
    host.ssh.known_hosts_path.write_text("RESTORED")
    with pytest.raises(TransportConfigError):
        await missing_bin.status(host, timeout_seconds=5)


async def test_ssh_macos_status_and_exec_no_gnu_timeout(tmp_path: Path):
    """macOS ARM64 (Zombie) works without /usr/bin/timeout on the remote host."""
    zombie = _make_host(
        tmp_path,
        "zombie",
        platform=HostPlatform.MACOS,
        host="zombie.local",
        user="macops",
        exec_enabled=True,
    )
    fake_ssh = _make_fake_ssh(
        tmp_path,
        """
import sys
cmd = sys.argv[-1]
assert "/usr/bin/timeout" not in cmd, f"unexpected GNU timeout in {cmd}"
if cmd == "uname -srm":
    sys.stdout.write("Darwin 24.1.0 arm64\\n")
    sys.exit(0)
if cmd == "/bin/bash --noprofile --norc -s":
    script = sys.stdin.read()
    assert "echo hello-zombie" in script
    sys.stdout.write("hello-zombie token=ghp_1234567890123456789012345\\n")
    sys.exit(0)
sys.exit(1)
""",
    )
    transport = SshHostTransport(ssh_bin=fake_ssh)

    st = await transport.status(zombie, timeout_seconds=5)
    assert st.host_id == "zombie"
    assert st.transport == "ssh"
    assert st.platform is HostPlatform.MACOS
    assert st.reachable is True
    assert st.os_info == "Darwin 24.1.0 arm64"

    res = await transport.exec_script(
        zombie, "echo hello-zombie", timeout_seconds=5, max_output_bytes=1024
    )
    assert res.host_id == "zombie"
    assert res.transport == "ssh"
    assert res.returncode == 0
    assert res.timed_out is False
    assert "hello-zombie" in res.output
    assert "ghp_1234567890123456789012345" not in res.output
    assert "[REDACTED]" in res.output


async def test_ssh_kule_side_timeout_kills_hung_process(tmp_path: Path):
    zombie = _make_host(tmp_path, "zombie", platform=HostPlatform.MACOS, exec_enabled=True)
    fake_ssh = _make_fake_ssh(
        tmp_path,
        """
import time
time.sleep(30)
""",
    )
    transport = SshHostTransport(ssh_bin=fake_ssh)
    res = await transport.exec_script(
        zombie, "sleep 30", timeout_seconds=0.3, max_output_bytes=1024
    )
    assert res.timed_out is True
    assert res.returncode is None
    assert res.error is not None and "timed out" in res.error

    with pytest.raises(HostUnreachableError, match="timed out"):
        await transport.status(zombie, timeout_seconds=0.3)


async def test_ssh_host_key_mismatch_and_offline_fail_closed(tmp_path: Path):
    host = _make_host(tmp_path, "gurbet")

    mismatch_ssh = _make_fake_ssh(
        tmp_path,
        """
import sys
sys.stderr.write("Host key verification failed.\\n")
sys.exit(255)
""",
    )
    with pytest.raises(HostKeyVerificationError):
        await SshHostTransport(ssh_bin=mismatch_ssh).status(host, timeout_seconds=5)

    offline_ssh = _make_fake_ssh(
        tmp_path,
        f"""
import sys
msg = "ssh: connect to host 192.0.2.10 port 22: Connection refused {host.ssh.key_path}\\n"
sys.stderr.write(msg)
sys.exit(255)
""",
    )
    with pytest.raises(HostUnreachableError) as exc_offline:
        await SshHostTransport(ssh_bin=offline_ssh).status(host, timeout_seconds=5)
    assert str(host.ssh.key_path) not in str(exc_offline.value)


async def test_ssh_read_command_validation_and_truncation(tmp_path: Path):
    host = _make_host(tmp_path, "gurbet")
    fake_ssh = _make_fake_ssh(
        tmp_path,
        """
import sys
sys.stdout.write("A" * 500)
sys.exit(0)
""",
    )
    transport = SshHostTransport(ssh_bin=fake_ssh)
    res = await transport.read_command(
        host, ["uptime"], timeout_seconds=5, max_output_bytes=64
    )
    assert res.returncode == 0
    assert res.truncated is True
    assert len(res.output) == 64

    with pytest.raises(ValueError):
        await transport.read_command(host, [], timeout_seconds=5, max_output_bytes=64)
    with pytest.raises(ValueError):
        await transport.read_command(
            host, ["echo", "bad\nline"], timeout_seconds=5, max_output_bytes=64
        )


# ---------------------------------------------------------------------------
# Integration tests: Multi-host MCP tools, RBAC, isolation, kill-switch, audit
# ---------------------------------------------------------------------------


class FakeMultiHostTransport:
    """In-memory HostTransport recording routed calls per host_id."""

    def __init__(self, *, fail_hosts: dict[str, Exception] | None = None) -> None:
        self.status_calls: list[str] = []
        self.exec_calls: list[tuple[str, str]] = []
        self.fail_hosts = fail_hosts or {}

    @property
    def transport_name(self) -> str:
        return "ssh"

    async def status(self, host: HostConfig, *, timeout_seconds: float) -> HostStatus:
        self.status_calls.append(host.host_id)
        if host.host_id in self.fail_hosts:
            raise self.fail_hosts[host.host_id]
        os_info = (
            "Darwin 24.1.0 arm64"
            if host.platform is HostPlatform.MACOS
            else "Linux 6.8.0 aarch64"
        )
        return HostStatus(
            host_id=host.host_id,
            transport="ssh",
            platform=host.platform,
            reachable=True,
            latency_ms=12,
            os_info=os_info,
        )

    async def read_command(
        self,
        host: HostConfig,
        command,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ExecResult:
        return ExecResult(
            host_id=host.host_id,
            transport="ssh",
            returncode=0,
            output="ok",
        )

    async def exec_script(
        self,
        host: HostConfig,
        script: str,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ExecResult:
        self.exec_calls.append((host.host_id, script))
        if host.host_id in self.fail_hosts:
            raise self.fail_hosts[host.host_id]
        return ExecResult(
            host_id=host.host_id,
            transport="ssh",
            returncode=0,
            output=f"ran on {host.host_id} secret=Bearer supersecrettoken12345",
            truncated=False,
            duration_ms=25,
        )


def _two_host_cfg(make_cfg, tmp_path: Path, *, global_exec: bool = False, **tools):
    gurbet = _make_host(
        tmp_path,
        "gurbet",
        platform=HostPlatform.LINUX,
        host="192.0.2.10",
        user="gurbet-ops",
        read_groups=frozenset({"ops"}),
        exec_groups=frozenset({"ops-exec"}),
        exec_enabled=True,
        description="Primary Linux node",
    )
    zombie = _make_host(
        tmp_path,
        "zombie",
        platform=HostPlatform.MACOS,
        host="192.0.2.20",
        user="zombie-ops",
        read_groups=frozenset({"ops"}),
        exec_groups=frozenset({"ops-exec"}),
        exec_enabled=False,
        description="macOS ARM64 workstation",
    )
    secret_box = _make_host(
        tmp_path,
        "secret-box",
        platform=HostPlatform.LINUX,
        host="192.0.2.99",
        user="root-ops",
        read_groups=frozenset({"other-team"}),
        exec_groups=frozenset({"other-exec"}),
        exec_enabled=True,
        description="Restricted host",
    )
    base = make_cfg(exec_enabled=global_exec, **tools)
    return replace(base, hosts=(gurbet, zombie, secret_box))


async def test_host_list_returns_only_authorized_hosts_and_no_secrets(
    make_cfg, claims, tmp_path: Path
):
    cfg = _two_host_cfg(make_cfg, tmp_path, global_exec=False)
    transport = FakeMultiHostTransport()
    mcp = build_server(cfg, claims_getter=claims, host_transport=transport)

    # Outsider cannot see or call host_list.
    claims.value = OUTSIDER
    async with Client(mcp) as client:
        tool_names = {t.name for t in await client.list_tools()}
        assert "host_list" not in tool_names
        assert "host_status" not in tool_names
        with pytest.raises(ToolError):
            await client.call_tool("host_list", {})

    # Operator sees only gurbet and zombie — never secret-box, never key paths or IPs.
    claims.value = OPERATOR
    async with Client(mcp) as client:
        res = await client.call_tool("host_list", {})
        hosts = res.data["hosts"]
        assert [h["host_id"] for h in hosts] == ["gurbet", "zombie"]
        raw_json = json.dumps(hosts)
        assert "secret-box" not in raw_json
        assert "id_ed25519" not in raw_json
        assert "known_hosts" not in raw_json
        assert "192.0.2." not in raw_json
        assert "gurbet-ops" not in raw_json


async def test_two_host_status_routing_and_denials(make_cfg, claims, tmp_path: Path):
    cfg = _two_host_cfg(make_cfg, tmp_path, global_exec=False)
    transport = FakeMultiHostTransport()
    mcp = build_server(cfg, claims_getter=claims, host_transport=transport)

    claims.value = OPERATOR
    async with Client(mcp) as client:
        r1 = await client.call_tool("host_status", {"host_id": "gurbet"})
        assert r1.data["host_id"] == "gurbet"
        assert r1.data["platform"] == "linux"
        assert r1.data["reachable"] is True
        assert "Linux" in r1.data["os_info"]

        r2 = await client.call_tool("host_status", {"host_id": "zombie"})
        assert r2.data["host_id"] == "zombie"
        assert r2.data["platform"] == "macos"
        assert r2.data["reachable"] is True
        assert "Darwin" in r2.data["os_info"]

        # Unknown host and unauthorized host are denied fail-closed.
        with pytest.raises(ToolError):
            await client.call_tool("host_status", {"host_id": "unknown-host"})
        with pytest.raises(ToolError):
            await client.call_tool("host_status", {"host_id": "secret-box"})

    assert transport.status_calls == ["gurbet", "zombie"]

    records = _read_audit(cfg.audit.path)
    assert any(
        r["event"] == "result"
        and r.get("host_id") == "zombie"
        and r.get("transport") == "ssh"
        and r.get("request_id")
        for r in records
    )
    assert any(
        r["event"] == "denied" and r.get("host_id") == "secret-box" for r in records
    )
    ok, count = verify_audit(cfg.audit.path)
    assert ok and count == len(records)


async def test_host_status_fails_closed_on_offline_and_host_key_mismatch(
    make_cfg, claims, tmp_path: Path
):
    cfg = _two_host_cfg(make_cfg, tmp_path, global_exec=False)
    transport = FakeMultiHostTransport(
        fail_hosts={
            "gurbet": HostKeyVerificationError(
                "SSH host key verification failed for host 'gurbet'"
            ),
            "zombie": HostUnreachableError("host 'zombie' unreachable: connection refused"),
        }
    )
    mcp = build_server(cfg, claims_getter=claims, host_transport=transport)

    claims.value = OPERATOR
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="host key verification failed"):
            await client.call_tool("host_status", {"host_id": "gurbet"})
        with pytest.raises(ToolError, match="unreachable"):
            await client.call_tool("host_status", {"host_id": "zombie"})

    ok, _ = verify_audit(cfg.audit.path)
    assert ok


async def test_host_exec_default_off_globally_and_per_host_isolation(
    make_cfg, claims, tmp_path: Path
):
    # 1. Global exec_enabled=False -> host_exec is not registered even when gurbet allows it.
    cfg_off = _two_host_cfg(make_cfg, tmp_path, global_exec=False)
    transport = FakeMultiHostTransport()
    mcp_off = build_server(cfg_off, claims_getter=claims, host_transport=transport)
    claims.value = {"sub": "owner", "groups": ["ops", "ops-exec"]}
    async with Client(mcp_off) as client:
        assert "host_exec" not in {t.name for t in await client.list_tools()}
        with pytest.raises(ToolError):
            await client.call_tool("host_exec", {"host_id": "gurbet", "script": "id"})

    # 2. Global exec_enabled=True: gurbet has exec_enabled=True, zombie has exec_enabled=False.
    cfg_on = _two_host_cfg(make_cfg, tmp_path, global_exec=True)
    mcp_on = build_server(cfg_on, claims_getter=claims, host_transport=transport)

    # Unauthorized callers (missing ops-exec or missing ops) are denied.
    for bad_claims in (
        OPERATOR,
        OUTSIDER,
        {"sub": "exec-only", "groups": ["ops-exec"]},
    ):
        claims.value = bad_claims
        async with Client(mcp_on) as client:
            assert "host_exec" not in {t.name for t in await client.list_tools()}
            with pytest.raises(ToolError):
                await client.call_tool("host_exec", {"host_id": "gurbet", "script": "id"})

    # Authorized caller can exec on gurbet, but NOT on zombie (exec_enabled=False) or secret-box.
    claims.value = {"sub": "owner", "groups": ["ops", "ops-exec"]}
    async with Client(mcp_on) as client:
        assert "host_exec" in {t.name for t in await client.list_tools()}

        res = await client.call_tool(
            "host_exec", {"host_id": "gurbet", "script": "id # private-canary-xyz"}
        )
        assert res.data["host_id"] == "gurbet"
        assert res.data["transport"] == "ssh"
        assert res.data["returncode"] == 0
        assert "supersecrettoken12345" not in res.data["output"]
        assert "[REDACTED]" in res.data["output"]

        # Per-host isolation: enabled on gurbet does NOT permit zombie.
        with pytest.raises(ToolError):
            await client.call_tool("host_exec", {"host_id": "zombie", "script": "id"})
        # Wrong/unauthorized host denied.
        with pytest.raises(ToolError):
            await client.call_tool("host_exec", {"host_id": "secret-box", "script": "id"})
        # Unknown host denied.
        with pytest.raises(ToolError):
            await client.call_tool("host_exec", {"host_id": "does-not-exist", "script": "id"})
        # Invalid script inputs rejected.
        for bad_script in ("", "   ", "x" * 16385, "echo \x00"):
            with pytest.raises(ToolError):
                await client.call_tool("host_exec", {"host_id": "gurbet", "script": bad_script})

    assert transport.exec_calls == [("gurbet", "id # private-canary-xyz")]

    audit_raw = cfg_on.audit.path.read_text()
    assert "private-canary-xyz" not in audit_raw
    assert "script_sha256" in audit_raw
    records = _read_audit(cfg_on.audit.path)
    assert any(
        r["event"] == "result"
        and r.get("tool") == "host_exec"
        and r.get("host_id") == "gurbet"
        and r.get("transport") == "ssh"
        and r.get("request_id")
        for r in records
    )
    assert any(
        r["event"] == "denied"
        and r.get("tool") == "host_exec"
        and r.get("host_id") == "zombie"
        and r.get("transport") == "ssh"
        for r in records
    )
    ok, count = verify_audit(cfg_on.audit.path)
    assert ok and count == len(records)


async def test_kill_switch_blocks_all_multi_host_tools(make_cfg, claims, tmp_path: Path):
    cfg = _two_host_cfg(make_cfg, tmp_path, global_exec=True)
    transport = FakeMultiHostTransport()
    mcp = build_server(cfg, claims_getter=claims, host_transport=transport)

    cfg.kill_switch_path.write_text("emergency stop")
    claims.value = {"sub": "owner", "groups": ["ops", "ops-exec"]}
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="kill switch"):
            await client.call_tool("host_list", {})
        with pytest.raises(ToolError, match="kill switch"):
            await client.call_tool("host_status", {"host_id": "gurbet"})
        with pytest.raises(ToolError, match="kill switch"):
            await client.call_tool("host_exec", {"host_id": "gurbet", "script": "id"})

    assert transport.status_calls == []
    assert transport.exec_calls == []
    records = _read_audit(cfg.audit.path)
    assert len(records) == 3
    assert all(r["event"] == "denied" and r["reason"] == "kill switch" for r in records)
    ok, count = verify_audit(cfg.audit.path)
    assert ok and count == 3


def test_single_host_v010_compatibility_when_no_hosts_configured(make_cfg, claims):
    cfg = make_cfg(exec_enabled=False)
    assert cfg.hosts == ()
    mcp = build_server(cfg, claims_getter=claims)
    # Multi-host tools are not registered when cfg.hosts is empty.
    claims.value = OPERATOR

    async def _check():
        async with Client(mcp) as client:
            names = {t.name for t in await client.list_tools()}
            assert "whoami" in names
            assert "host_list" not in names
            assert "host_status" not in names

    import asyncio

    asyncio.run(_check())


async def test_host_exec_not_registered_when_all_hosts_disable_exec(
    make_cfg, claims, tmp_path: Path
):
    zombie = _make_host(tmp_path, "zombie", platform=HostPlatform.MACOS, exec_enabled=False)
    cfg = replace(make_cfg(exec_enabled=True), hosts=(zombie,))
    mcp = build_server(cfg, claims_getter=claims, host_transport=FakeMultiHostTransport())
    claims.value = {"sub": "owner", "groups": ["ops", "ops-exec"]}
    async with Client(mcp) as client:
        names = {t.name for t in await client.list_tools()}
        assert "host_list" in names
        assert "host_status" in names
        assert "host_exec" not in names
        with pytest.raises(ToolError):
            await client.call_tool("host_exec", {"host_id": "zombie", "script": "id"})


def test_host_exec_rejects_shared_developer_runtime(make_cfg, claims, tmp_path: Path):
    cfg = _two_host_cfg(
        make_cfg,
        tmp_path,
        global_exec=True,
        workspace_enabled=True,
        developer_enabled=True,
    )
    with pytest.raises(RuntimeError, match="developer runtime"):
        build_server(cfg, claims_getter=claims, host_transport=FakeMultiHostTransport())
