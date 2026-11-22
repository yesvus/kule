"""Contract tests for the default-off host SSH backend."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from helpers import OPERATOR, OUTSIDER

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
