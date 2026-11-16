import json

import pytest
from conftest import OPERATOR, OUTSIDER
from fastmcp import Client
from fastmcp.exceptions import ToolError

from operator_mcp.audit import verify
from operator_mcp.server import build_server


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


async def test_note_write_rejects_path_tricks(server, claims):
    cfg, mcp = server
    claims.value = OPERATOR
    async with Client(mcp) as client:
        for bad in ("../etc", "a/b", "UPPER", ""):
            with pytest.raises(ToolError):
                await client.call_tool("note_write", {"name": bad, "text": "x"})
    assert not any(cfg.tools.scratch_dir.glob("*")) if cfg.tools.scratch_dir.exists() else True


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
