import json

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from helpers import OPERATOR, OUTSIDER

from kule.audit import AuditLog, verify
from kule.server import build_server


@pytest.fixture
def server(make_cfg, claims):
    cfg = make_cfg()
    return cfg, build_server(cfg, claims_getter=claims)


def audit_events(cfg):
    return [json.loads(line) for line in cfg.audit.path.read_text().splitlines()]


async def test_operator_sees_and_calls_tools(server, claims):
    cfg, mcp = server
    claims.value = OPERATOR
    async with Client(mcp) as client:
        names = {t.name for t in await client.list_tools()}
        assert names == {"whoami", "note_write"}
        who = await client.call_tool("whoami", {})
        assert who.data["user"] == "owner"
        res = await client.call_tool("note_write", {"name": "hello", "text": "hi"})
        assert res.data["bytes"] == 2
    assert (cfg.tools.scratch_dir / "hello.txt").read_text() == "hi"
    events = [e["event"] for e in audit_events(cfg)]
    assert events == ["call", "result", "call", "result"]
    assert all(e["user"] == "owner" for e in audit_events(cfg))
    assert verify(cfg.audit.path) == (True, 4)


@pytest.mark.parametrize("who", [None, OUTSIDER])
async def test_unauthorized_callers_see_nothing_and_are_denied(server, claims, who):
    cfg, mcp = server
    claims.value = who
    async with Client(mcp) as client:
        assert await client.list_tools() == []
        with pytest.raises(ToolError):
            await client.call_tool("note_write", {"name": "x", "text": "y"})
    assert not (cfg.tools.scratch_dir / "x.txt").exists()
    assert audit_events(cfg)[-1]["event"] == "denied"


async def test_kill_switch_blocks_operator(server, claims):
    cfg, mcp = server
    claims.value = OPERATOR
    cfg.kill_switch_path.touch()
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="kill switch"):
            await client.call_tool("whoami", {})
    assert audit_events(cfg)[-1]["reason"] == "kill switch"


async def test_kill_switch_activated_during_audit_blocks_dispatch(server, claims, monkeypatch):
    cfg, mcp = server
    claims.value = OPERATOR
    original_write = AuditLog.write

    def activate_after_call_audit(self, event, **fields):
        original_write(self, event, **fields)
        if event == "call":
            cfg.kill_switch_path.touch()

    monkeypatch.setattr(AuditLog, "write", activate_after_call_audit)
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="kill switch"):
            await client.call_tool("note_write", {"name": "blocked", "text": "x"})

    assert not (cfg.tools.scratch_dir / "blocked.txt").exists()
    events = audit_events(cfg)
    assert [e["event"] for e in events] == ["call", "denied"]
    assert events[-1]["reason"] == "kill switch"
    assert events[0]["call_id"] == events[1]["call_id"]
    assert verify(cfg.audit.path) == (True, 2)


async def test_note_write_rejects_path_tricks(server, claims):
    cfg, mcp = server
    claims.value = OPERATOR
    async with Client(mcp) as client:
        for bad in ("../etc", "a/b", "UPPER", "", "abc\n", "-lead"):
            with pytest.raises(ToolError):
                await client.call_tool("note_write", {"name": bad, "text": "x"})
    assert not cfg.tools.scratch_dir.exists()


async def test_audit_redacts_secrets_in_arguments(server, claims):
    cfg, mcp = server
    claims.value = OPERATOR
    secret = "ghp_" + "a" * 36
    async with Client(mcp) as client:
        await client.call_tool("note_write", {"name": "s", "text": f"token={secret}"})
    raw = cfg.audit.path.read_text()
    assert secret not in raw
    assert secret not in (cfg.tools.scratch_dir / "s.txt").read_text()


async def test_read_tools_are_marked_read_only(server, claims):
    _, mcp = server
    claims.value = OPERATOR
    async with Client(mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
    assert tools["whoami"].annotations.read_only_hint is True
    assert tools["note_write"].annotations.read_only_hint is False


async def test_denial_message_does_not_leak_policy(server, claims):
    cfg, mcp = server
    claims.value = OUTSIDER
    async with Client(mcp) as client:
        with pytest.raises(ToolError) as exc:
            await client.call_tool("whoami", {})
    assert "ops" not in str(exc.value)
    assert audit_events(cfg)[-1]["reason"] == "caller is not in ops"


def _extra_tools(mcp):
    import asyncio

    @mcp.tool(tags={"read"})
    def big() -> str:
        return "x" * 200_000

    @mcp.tool(tags={"read"})
    async def inner_timeout() -> str:
        raise TimeoutError("upstream took too long")

    @mcp.tool(tags={"read"})
    async def slow() -> str:
        await asyncio.sleep(5)
        return "late"


async def test_output_cap_timeout_and_inner_timeout(make_cfg, claims):
    from kule.server import build_server

    cfg = make_cfg(timeout_seconds=1.0)
    mcp = build_server(cfg, claims_getter=claims)
    _extra_tools(mcp)
    claims.value = OPERATOR
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="exceeds"):
            await client.call_tool("big", {})
        with pytest.raises(ToolError):
            await client.call_tool("inner_timeout", {})
        with pytest.raises(ToolError, match="timed out"):
            await client.call_tool("slow", {})
    events = [(e["tool"], e["event"]) for e in audit_events(cfg) if e["event"] != "call"]
    assert events == [("big", "oversize"), ("inner_timeout", "error"), ("slow", "timeout")]
    assert verify(cfg.audit.path)[0]


async def test_note_file_is_private(server, claims):
    cfg, mcp = server
    claims.value = OPERATOR
    async with Client(mcp) as client:
        await client.call_tool("note_write", {"name": "p", "text": "x"})
    assert ((cfg.tools.scratch_dir / "p.txt").stat().st_mode & 0o777) == 0o600


async def test_whoami_falls_back_to_subject(server, claims):
    _, mcp = server
    claims.value = {"sub": "only-sub", "groups": ["ops"]}
    async with Client(mcp) as client:
        who = await client.call_tool("whoami", {})
    assert who.data["user"] == "only-sub"


def test_fastmcp_home_is_forced(make_cfg, monkeypatch):
    import os

    from kule import server as srv

    monkeypatch.setenv("FASTMCP_HOME", "/elsewhere")
    cfg = make_cfg()

    class Stop(Exception):
        pass

    def fake_proxy(**kwargs):
        raise Stop

    monkeypatch.setattr(srv, "AuthentikRefreshOIDCProxy", fake_proxy)
    with pytest.raises(Stop):
        srv.build_auth(cfg)
    assert os.environ["FASTMCP_HOME"] == str(cfg.server.state_dir / "fastmcp")


async def test_single_host_image_only_registers_base_tools(make_cfg, claims, monkeypatch):
    """Release image never exposes the legacy integration tool collection."""
    monkeypatch.setenv("KULE_SINGLE_HOST_IMAGE", "1")
    monkeypatch.delenv("KULE_K8S_API_URL", raising=False)
    monkeypatch.delenv("KULE_K8S_UPSTREAM_ENABLED", raising=False)
    monkeypatch.delenv("KULE_ARGOCD_UPSTREAM_ENABLED", raising=False)
    monkeypatch.delenv("KULE_OPENHANDS_ENABLED", raising=False)
    claims.value = OPERATOR
    mcp = build_server(make_cfg(), claims_getter=claims)
    async with Client(mcp) as client:
        assert {tool.name for tool in await client.list_tools()} == {"whoami", "note_write"}


@pytest.mark.parametrize(
    "flag,value",
    [
        ("KULE_K8S_API_URL", "https://localhost:6443"),
        ("KULE_K8S_UPSTREAM_ENABLED", "1"),
        ("KULE_ARGOCD_UPSTREAM_ENABLED", "1"),
        ("KULE_OPENHANDS_ENABLED", "1"),
    ],
)
def test_single_host_image_rejects_legacy_integrations(make_cfg, claims, monkeypatch, flag, value):
    monkeypatch.setenv("KULE_SINGLE_HOST_IMAGE", "1")
    monkeypatch.setenv(flag, value)
    with pytest.raises(RuntimeError, match="Single-host Kule image"):
        build_server(make_cfg(), claims_getter=claims)


@pytest.mark.parametrize("option", ["workspace_enabled", "developer_enabled"])
def test_single_host_image_rejects_workspace_config(make_cfg, claims, monkeypatch, option):
    monkeypatch.setenv("KULE_SINGLE_HOST_IMAGE", "1")
    with pytest.raises(RuntimeError, match="Single-host Kule image"):
        build_server(make_cfg(**{option: True}), claims_getter=claims)


def test_single_host_marker_cannot_be_overridden_by_environment(
    make_cfg, claims, monkeypatch, tmp_path
):
    from kule import server

    marker = tmp_path / "SINGLE_HOST_IMAGE"
    marker.touch()
    monkeypatch.setattr(server, "_SINGLE_HOST_MARKER", marker)
    monkeypatch.setenv("KULE_SINGLE_HOST_IMAGE", "0")
    monkeypatch.setenv("KULE_K8S_API_URL", "https://localhost:6443")
    with pytest.raises(RuntimeError, match="Single-host Kule image"):
        build_server(make_cfg(), claims_getter=claims)


async def test_single_host_image_retains_opt_in_ssh_tool(
    make_cfg, claims, monkeypatch, tmp_path
):
    from kule.tools import host_exec as ssh_tool

    monkeypatch.setenv("KULE_SINGLE_HOST_IMAGE", "1")
    monkeypatch.setenv("KULE_HOST_EXEC_ENABLED", "1")
    monkeypatch.setenv("KULE_HOST_EXEC_TARGET", "operator@host.example.com")
    for name in ("id_ed25519", "known_hosts", "ssh"):
        (tmp_path / name).touch()
    monkeypatch.setattr(ssh_tool, "_KEY", tmp_path / "id_ed25519")
    monkeypatch.setattr(ssh_tool, "_KNOWN_HOSTS", tmp_path / "known_hosts")
    monkeypatch.setattr(ssh_tool, "_SSH", str(tmp_path / "ssh"))

    cfg = make_cfg(exec_enabled=True, timeout_seconds=45)
    claims.value = {**OPERATOR, "groups": ["ops", "ops-exec"]}
    mcp = build_server(cfg, claims_getter=claims)
    async with Client(mcp) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert names == {"whoami", "note_write", "host_exec"}
