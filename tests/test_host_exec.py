"""Contract tests for the default-off host SSH backend."""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from helpers import OPERATOR, OUTSIDER

from kule.audit import verify
from kule.server import build_server
from kule.tools import host_exec


async def test_host_exec_default_off(make_cfg, claims, monkeypatch):
    monkeypatch.delenv("KULE_HOST_EXEC_ENABLED", raising=False)
    claims.value = {"sub": "owner", "groups": ["ops", "ops-exec"]}
    async with Client(build_server(make_cfg(exec_enabled=True), claims_getter=claims)) as client:
        assert "host_exec" not in {t.name for t in await client.list_tools()}
        with pytest.raises(ToolError):
            await client.call_tool("host_exec", {"script": "id"})


async def test_host_exec_requires_both_groups_and_audits_digest(make_cfg, claims, monkeypatch):
    monkeypatch.setenv("KULE_HOST_EXEC_ENABLED", "1")
    monkeypatch.setenv("KULE_HOST_EXEC_TARGET", "user@host.example")
    monkeypatch.setattr(host_exec, "Path", lambda name: SimpleNamespace(is_file=lambda: True))
    monkeypatch.setattr(host_exec, "_KEY", SimpleNamespace(is_file=lambda: True))
    monkeypatch.setattr(host_exec, "_KNOWN_HOSTS", SimpleNamespace(is_file=lambda: True))
    calls = []

    async def fake_run(script, seconds, max_bytes):
        calls.append(script)
        assert seconds == 20
        assert 0 < max_bytes <= 16384
        return {"host": "gurbet", "returncode": 0, "output": "uid=1002", "truncated": False}

    monkeypatch.setattr(host_exec, "_run", fake_run)
    cfg = make_cfg(exec_enabled=True)
    mcp = build_server(cfg, claims_getter=claims)
    for group_claims in (
        OPERATOR,
        OUTSIDER,
        {"sub": "worker", "groups": ["mcp-developers", "mcp-workspace"]},
        {"sub": "exec-only", "groups": ["ops-exec"]},
    ):
        claims.value = group_claims
        async with Client(mcp) as client:
            assert "host_exec" not in {t.name for t in await client.list_tools()}
            with pytest.raises(ToolError):
                await client.call_tool("host_exec", {"script": "id"})
    claims.value = {"sub": "owner", "groups": ["ops", "ops-exec"]}
    async with Client(mcp) as client:
        assert "host_exec" in {t.name for t in await client.list_tools()}
        result = await client.call_tool("host_exec", {"script": "id # synthetic-private-canary"})
        assert result.data["returncode"] == 0
        for script in ("", "x" * 16385, "\x00"):
            with pytest.raises(ToolError):
                await client.call_tool("host_exec", {"script": script})
    assert calls == [b"id # synthetic-private-canary"]
    audit = cfg.audit.path.read_text()
    assert "synthetic-private-canary" not in audit
    assert "script_sha256" in audit


def test_ssh_command_is_fixed_and_strict(monkeypatch):
    monkeypatch.setenv("KULE_HOST_EXEC_TARGET", "user@host.example")
    args = host_exec._argv(20)
    assert args[-2] == "user@host.example"
    assert "StrictHostKeyChecking=yes" in args
    assert "IdentityAgent=none" in args
    assert "ClearAllForwardings=yes" in args
    assert "BatchMode=yes" in args
    assert args[-1].endswith("/bin/bash --noprofile --norc -s")


def test_ssh_target_is_required_and_fixed(monkeypatch):
    monkeypatch.delenv("KULE_HOST_EXEC_TARGET", raising=False)
    with pytest.raises(RuntimeError, match="KULE_HOST_EXEC_TARGET"):
        host_exec._argv(20)
    for target in ("-oProxyCommand=whoami", "user@host;whoami", "user@host/path"):
        monkeypatch.setenv("KULE_HOST_EXEC_TARGET", target)
        with pytest.raises(RuntimeError, match="KULE_HOST_EXEC_TARGET"):
            host_exec._argv(20)


def _enable_fake_ssh(monkeypatch, tmp_path: Path) -> Path:
    """Configure host_exec prerequisites with a local fake ssh executable."""
    key = tmp_path / "id_ed25519"
    known_hosts = tmp_path / "known_hosts"
    fake_ssh = tmp_path / "fake-ssh"
    key.write_text("synthetic-key")
    known_hosts.write_text("host.example ssh-ed25519 AAAA")
    fake_ssh.write_text(
        '#!/bin/sh\nfor arg in "$@"; do\n    cmd="$arg"\ndone\nexec /bin/sh -c "$cmd"\n'
    )
    fake_ssh.chmod(0o700)
    monkeypatch.setenv("KULE_HOST_EXEC_ENABLED", "1")
    monkeypatch.setenv("KULE_HOST_EXEC_TARGET", "user@host.example")
    monkeypatch.setattr(host_exec, "_KEY", key)
    monkeypatch.setattr(host_exec, "_KNOWN_HOSTS", known_hosts)
    monkeypatch.setattr(host_exec, "_SSH", str(fake_ssh))
    return fake_ssh


def _audit_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _assert_process_gone(pid: int, timeout: float = 1.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    pytest.fail(f"process {pid} is still running after timeout cleanup")


@pytest.mark.parametrize(
    "configured,expected",
    [
        (15, "5.0"),
        (15.5, "5.5"),
        (25.3, "15.3"),
        (30, "20.0"),
        (45, "35.0"),
        (110, "90.0"),
    ],
)
async def test_host_exec_description_states_effective_timeout(
    make_cfg, claims, monkeypatch, tmp_path, configured, expected
):
    _enable_fake_ssh(monkeypatch, tmp_path)
    cfg = make_cfg(exec_enabled=True, timeout_seconds=configured)
    claims.value = {"sub": "owner", "groups": ["ops", "ops-exec"]}
    mcp = build_server(cfg, claims_getter=claims)
    async with Client(mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
    tool = tools["host_exec"]
    desc = tool.description or ""
    assert f"{expected}s" in desc
    assert (
        "processes that detach with setsid or double-fork are not stopped at the deadline" in desc
    )
    assert set(tool.input_schema.get("properties", {})) == {"script"}


async def test_host_exec_fractional_timeout_kept_and_formatted_consistently(
    make_cfg, claims, monkeypatch, tmp_path
):
    _enable_fake_ssh(monkeypatch, tmp_path)
    assert (
        host_exec._effective_timeout_seconds(make_cfg(exec_enabled=True, timeout_seconds=15.5))
        == 5.5
    )
    assert (
        host_exec._effective_timeout_seconds(make_cfg(exec_enabled=True, timeout_seconds=15.25))
        == 5.25
    )
    assert (
        host_exec._effective_timeout_seconds(make_cfg(exec_enabled=True, timeout_seconds=15.3))
        == 5.3
    )
    assert " 5.5s " in host_exec._argv(5.5)[-1]
    assert " 5.25s " in host_exec._argv(5.25)[-1]

    cfg = make_cfg(exec_enabled=True, timeout_seconds=15.5)
    claims.value = {"sub": "owner", "preferred_username": "owner", "groups": ["ops", "ops-exec"]}
    mcp = build_server(cfg, claims_getter=claims)
    async with Client(mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
        assert "5.5s" in (tools["host_exec"].description or "")
        result = await client.call_tool("host_exec", {"script": "echo ok\n"})
    assert result.data["timed_out"] is False
    assert result.data["timeout_seconds"] == 5.5

    # Also verify a fractional budget actually enforces timeout and reports consistently.
    monkeypatch.setattr(host_exec, "_effective_timeout_seconds", lambda _cfg: 0.5)
    mcp_short = build_server(cfg, claims_getter=claims)
    async with Client(mcp_short) as client:
        tools = {t.name: t for t in await client.list_tools()}
        assert "0.5s" in (tools["host_exec"].description or "")
        timed = await client.call_tool("host_exec", {"script": "echo frac-start\nsleep 10\n"})
    assert timed.data["timed_out"] is True
    assert timed.data["timeout_seconds"] == 0.5
    assert timed.data["returncode"] == 124
    assert "frac-start" in timed.data["output"]
    events = _audit_events(cfg.audit.path)
    assert events[-1]["event"] == "timeout"
    assert events[-1]["timeout_seconds"] == 0.5


@pytest.mark.parametrize("status", [124, 137])
async def test_host_exec_immediate_exit_124_or_137_not_timed_out(
    make_cfg, claims, monkeypatch, tmp_path, status
):
    _enable_fake_ssh(monkeypatch, tmp_path)
    cfg = make_cfg(exec_enabled=True, timeout_seconds=30)
    claims.value = {"sub": "owner", "preferred_username": "owner", "groups": ["ops", "ops-exec"]}
    mcp = build_server(cfg, claims_getter=claims)
    async with Client(mcp) as client:
        result = await client.call_tool(
            "host_exec",
            {"script": f"echo immediate-{status}\nexit {status}\n"},
        )
    assert result.data["timed_out"] is False
    assert result.data["returncode"] == status
    assert f"immediate-{status}" in result.data["output"]
    events = _audit_events(cfg.audit.path)
    assert [e["event"] for e in events] == ["call", "result"]
    assert verify(cfg.audit.path) == (True, 2)


async def test_host_exec_normal_call_unchanged(make_cfg, claims, monkeypatch, tmp_path):
    _enable_fake_ssh(monkeypatch, tmp_path)
    cfg = make_cfg(exec_enabled=True, timeout_seconds=30)
    claims.value = {"sub": "owner", "preferred_username": "owner", "groups": ["ops", "ops-exec"]}
    mcp = build_server(cfg, claims_getter=claims)
    async with Client(mcp) as client:
        result = await client.call_tool(
            "host_exec",
            {"script": "echo normal-stdout\necho normal-stderr >&2\n"},
        )
    assert result.data["host"] == "configured-host"
    assert result.data["returncode"] == 0
    assert result.data["timed_out"] is False
    assert result.data["timeout_seconds"] == 20
    assert result.data["truncated"] is False
    assert "normal-stdout" in result.data["output"]
    assert "normal-stderr" in result.data["output"]
    events = _audit_events(cfg.audit.path)
    assert [e["event"] for e in events] == ["call", "result"]
    assert events[0]["call_id"] == events[1]["call_id"]
    assert verify(cfg.audit.path) == (True, 2)


async def test_host_exec_timeout_returns_partial_output_kills_child_and_audits(
    make_cfg, claims, monkeypatch, tmp_path
):
    _enable_fake_ssh(monkeypatch, tmp_path)
    monkeypatch.setattr(host_exec, "_effective_timeout_seconds", lambda _cfg: 1)
    cfg = make_cfg(exec_enabled=True, timeout_seconds=15)
    claims.value = {"sub": "owner", "preferred_username": "owner", "groups": ["ops", "ops-exec"]}
    mcp = build_server(cfg, claims_getter=claims)

    pidfile = tmp_path / "child.pid"
    secret = "ghp_" + "a" * 36
    script = (
        f"echo step1-stdout\n"
        f"echo step2-stderr >&2\n"
        f"echo token={secret}\n"
        f"sleep 30 &\n"
        f"echo $! > {shlex.quote(str(pidfile))}\n"
        f"wait\n"
    )
    async with Client(mcp) as client:
        result = await client.call_tool("host_exec", {"script": script})

    assert result.data["host"] == "configured-host"
    assert result.data["timed_out"] is True
    assert result.data["timeout_seconds"] == 1
    assert result.data["returncode"] == 124
    assert result.data["truncated"] is False
    assert "step1-stdout" in result.data["output"]
    assert "step2-stderr" in result.data["output"]
    assert secret not in result.data["output"]
    assert "[REDACTED]" in result.data["output"]

    assert pidfile.is_file()
    _assert_process_gone(int(pidfile.read_text().strip()))

    raw_audit = cfg.audit.path.read_text()
    assert secret not in raw_audit
    assert "step1-stdout" not in raw_audit
    events = _audit_events(cfg.audit.path)
    assert [e["event"] for e in events] == ["call", "timeout"]
    assert events[0]["call_id"] == events[1]["call_id"]
    timeout_event = events[1]
    assert timeout_event["tool"] == "host_exec"
    assert timeout_event["user"] == "owner"
    assert timeout_event["sub"] == "owner"
    assert timeout_event["timeout_seconds"] == 1
    assert timeout_event["returncode"] == 124
    assert timeout_event["bytes"] > 0
    assert isinstance(timeout_event["duration_ms"], int)
    assert verify(cfg.audit.path) == (True, 2)


async def test_host_exec_local_timeout_kills_process_group_including_trapped_child(
    make_cfg, claims, monkeypatch, tmp_path
):
    _enable_fake_ssh(monkeypatch, tmp_path)
    # Bypass /usr/bin/timeout to exercise host_exec's own local timeout and
    # process-group SIGTERM -> SIGKILL cleanup.
    monkeypatch.setattr(
        host_exec, "_argv", lambda _seconds: ["/bin/bash", "--noprofile", "--norc", "-s"]
    )
    monkeypatch.setattr(host_exec, "_effective_timeout_seconds", lambda _cfg: 1)
    monkeypatch.setattr(host_exec, "_LOCAL_TIMEOUT_GRACE", 0.0)
    monkeypatch.setattr(host_exec, "_KILL_GRACE", 0.2)
    cfg = make_cfg(exec_enabled=True, timeout_seconds=15)
    claims.value = {"sub": "owner", "preferred_username": "owner", "groups": ["ops", "ops-exec"]}
    mcp = build_server(cfg, claims_getter=claims)

    pidfile = tmp_path / "trapped.pid"
    script = (
        f"echo local-partial-out\n"
        f"echo local-partial-err >&2\n"
        f"(trap '' TERM; sleep 30) &\n"
        f"echo $! > {shlex.quote(str(pidfile))}\n"
        f"wait\n"
    )
    async with Client(mcp) as client:
        result = await client.call_tool("host_exec", {"script": script})

    assert result.data["timed_out"] is True
    assert result.data["timeout_seconds"] == 1
    assert result.data["returncode"] != 0
    assert "local-partial-out" in result.data["output"]
    assert "local-partial-err" in result.data["output"]

    assert pidfile.is_file()
    _assert_process_gone(int(pidfile.read_text().strip()))

    events = _audit_events(cfg.audit.path)
    assert [e["event"] for e in events] == ["call", "timeout"]
    assert verify(cfg.audit.path) == (True, 2)


async def test_host_exec_timeout_enforces_output_size_bound(
    make_cfg, claims, monkeypatch, tmp_path
):
    _enable_fake_ssh(monkeypatch, tmp_path)
    monkeypatch.setattr(host_exec, "_effective_timeout_seconds", lambda _cfg: 1)
    cfg = make_cfg(exec_enabled=True, timeout_seconds=15, max_output_bytes=2048)
    claims.value = {"sub": "owner", "preferred_username": "owner", "groups": ["ops", "ops-exec"]}
    mcp = build_server(cfg, claims_getter=claims)

    script = "printf '%0.sA' $(seq 1 1000)\nsleep 30\n"
    async with Client(mcp) as client:
        result = await client.call_tool("host_exec", {"script": script})

    assert result.data["timed_out"] is True
    assert result.data["timeout_seconds"] == 1
    assert result.data["truncated"] is True
    assert len(result.data["output"].encode("utf-8")) <= 128
    assert result.data["output"] == "A" * 128

    events = _audit_events(cfg.audit.path)
    assert [e["event"] for e in events] == ["call", "timeout"]
    assert events[1]["truncated"] is True
    assert verify(cfg.audit.path) == (True, 2)


async def test_host_exec_cancellation_kills_process_group(monkeypatch, tmp_path):
    monkeypatch.setattr(
        host_exec, "_argv", lambda _seconds: ["/bin/bash", "--noprofile", "--norc", "-s"]
    )
    pidfile = tmp_path / "cancelled.pid"
    script = f"echo started\nsleep 30 &\necho $! > {shlex.quote(str(pidfile))}\nwait\n".encode()

    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.4):
            await host_exec._run(script, seconds=10, max_bytes=4096)

    assert pidfile.is_file()
    _assert_process_gone(int(pidfile.read_text().strip()))


async def test_host_exec_chatty_script_killed_at_deadline_returns_promptly(
    make_cfg, claims, monkeypatch, tmp_path
):
    _enable_fake_ssh(monkeypatch, tmp_path)
    monkeypatch.setattr(
        host_exec, "_argv", lambda _seconds: ["/bin/bash", "--noprofile", "--norc", "-s"]
    )
    monkeypatch.setattr(host_exec, "_effective_timeout_seconds", lambda _cfg: 0.4)
    monkeypatch.setattr(host_exec, "_LOCAL_TIMEOUT_GRACE", 0.0)
    monkeypatch.setattr(host_exec, "_KILL_GRACE", 0.3)
    cfg = make_cfg(exec_enabled=True, timeout_seconds=15, max_output_bytes=2048)
    claims.value = {"sub": "owner", "preferred_username": "owner", "groups": ["ops", "ops-exec"]}
    mcp = build_server(cfg, claims_getter=claims)

    pidfile = tmp_path / "chatty.pid"
    script = (
        f"yes AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA &\n"
        f"echo $! > {shlex.quote(str(pidfile))}\n"
        f"yes BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB >&2\n"
    )
    started = time.monotonic()
    async with Client(mcp) as client:
        result = await client.call_tool("host_exec", {"script": script})
    elapsed = time.monotonic() - started

    assert elapsed < 1.5
    assert result.data["timed_out"] is True
    assert result.data["timeout_seconds"] == 0.4
    assert result.data["truncated"] is True
    assert len(result.data["output"].encode("utf-8")) <= 128
    assert pidfile.is_file()
    _assert_process_gone(int(pidfile.read_text().strip()))
    events = _audit_events(cfg.audit.path)
    assert [e["event"] for e in events] == ["call", "timeout"]
    assert verify(cfg.audit.path) == (True, 2)


async def test_host_exec_drains_output_during_sigterm_termination(
    make_cfg, claims, monkeypatch, tmp_path
):
    _enable_fake_ssh(monkeypatch, tmp_path)
    monkeypatch.setattr(
        host_exec, "_argv", lambda _seconds: ["/bin/bash", "--noprofile", "--norc", "-s"]
    )
    monkeypatch.setattr(host_exec, "_effective_timeout_seconds", lambda _cfg: 0.3)
    monkeypatch.setattr(host_exec, "_LOCAL_TIMEOUT_GRACE", 0.0)
    # Use a long _KILL_GRACE so blocking on an undrained pipe during wait()
    # would delay return by >= 2.3s instead of exiting promptly on SIGTERM.
    monkeypatch.setattr(host_exec, "_KILL_GRACE", 2.0)
    cfg = make_cfg(exec_enabled=True, timeout_seconds=15, max_output_bytes=2048)
    claims.value = {"sub": "owner", "preferred_username": "owner", "groups": ["ops", "ops-exec"]}
    mcp = build_server(cfg, claims_getter=claims)

    pidfile = tmp_path / "sleeper.pid"
    # On SIGTERM, write 256 KiB (exceeding the 64 KiB pipe buffer) then exit.
    script = (
        "trap 'dd if=/dev/zero bs=4096 count=64 2>/dev/null | tr \"\\0\" Z; exit 0' TERM\n"
        "echo ready\n"
        "sleep 30 &\n"
        f"echo $! > {shlex.quote(str(pidfile))}\n"
        "wait\n"
    )
    started = time.monotonic()
    async with Client(mcp) as client:
        result = await client.call_tool("host_exec", {"script": script})
    elapsed = time.monotonic() - started

    assert elapsed < 1.3
    assert result.data["timed_out"] is True
    assert result.data["timeout_seconds"] == 0.3
    assert result.data["returncode"] == 124
    assert result.data["truncated"] is True
    assert "ready" in result.data["output"]
    assert len(result.data["output"].encode("utf-8")) <= 128
    assert pidfile.is_file()
    _assert_process_gone(int(pidfile.read_text().strip()))
    events = _audit_events(cfg.audit.path)
    assert [e["event"] for e in events] == ["call", "timeout"]
    assert verify(cfg.audit.path) == (True, 2)


async def test_other_tools_keep_timeout_behaviour_when_host_exec_enabled(
    make_cfg, claims, monkeypatch, tmp_path
):
    _enable_fake_ssh(monkeypatch, tmp_path)
    cfg = make_cfg(exec_enabled=True, timeout_seconds=15)
    claims.value = {"sub": "owner", "preferred_username": "owner", "groups": ["ops", "ops-exec"]}
    mcp = build_server(cfg, claims_getter=claims)

    @mcp.tool(tags={"read"})
    async def other_timed_out_dict() -> dict:
        return {"timed_out": True, "output": "custom"}

    async with Client(mcp) as client:
        res = await client.call_tool("other_timed_out_dict", {})
    assert res.data == {"timed_out": True, "output": "custom"}
    events = _audit_events(cfg.audit.path)
    assert [e["event"] for e in events] == ["call", "result"]
