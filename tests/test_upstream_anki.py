"""Synthetic upstream contract; never connects to a real Anki collection."""

import json

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware

from operator_mcp.audit import AuditLog, verify
from operator_mcp.authz import Policy
from operator_mcp.config import ConfigError, validate_anki_mcp_url
from operator_mcp.middleware import OperatorMiddleware
from operator_mcp.tools import upstream_anki as upstream


def test_fixed_private_endpoint_rejects_public_or_altered_urls():
    expected = "http://anki-mcp.anki.svc.cluster.local:3142/mcp"
    assert validate_anki_mcp_url(expected) == expected
    assert validate_anki_mcp_url("") is None
    for bad in (
        "https://anki-mcp.anki.svc.cluster.local:3142/mcp",
        "http://127.0.0.1:3142/mcp",
        "http://example.com:3142/mcp",
        "http://anki-mcp.anki.svc.cluster.local:3142/other",
        "http://anki-mcp.anki.svc.cluster.local:3142/mcp?url=x",
        "http://user@anki-mcp.anki.svc.cluster.local:3142/mcp",
        " http://anki-mcp.anki.svc.cluster.local:3142/mcp",
        "http://anki-mcp.anki.svc.cluster.local:3142/\nmcp",
        "http://anki-mcp.anki.svc.cluster.local:3142/m\tcp",
    ):
        with pytest.raises(ConfigError, match="fixed private MCP endpoint"):
            validate_anki_mcp_url(bad)


def _gateway(identity, audit_path, tmp_path):
    policy = Policy(
        required_group="ops",
        exec_group="exec",
        exec_enabled=False,
        anki_read_group="anki-readers",
        anki_write_group="anki-writers",
    )
    gateway = FastMCP(
        "kule-anki-synthetic",
        middleware=[
            OperatorMiddleware(
                policy=policy,
                audit=AuditLog(audit_path),
                kill_switch=tmp_path / "DISABLED",
                timeout_seconds=5,
                max_output_bytes=4096,
                claims_getter=lambda: identity["claims"],
            )
        ],
    )

    @gateway.tool(tags={"read"})
    def whoami() -> str:
        return "kule-ok"

    return gateway


async def test_anki_allowlist_and_separate_discovery_and_invocation(tmp_path):
    backend = FastMCP("synthetic-anki")

    @backend.tool()
    def listDecks() -> list[str]:
        return ["Fixture"]

    @backend.tool()
    def findNotes(query: str) -> list[int]:
        return [1]

    @backend.tool()
    def notesInfo(notes: list[int]) -> list[dict]:
        return [{"noteId": note, "fields": {"Front": "private-study-text"}} for note in notes]

    @backend.tool()
    def addNotes(deckName: str, modelName: str, notes: list[dict], allowDuplicate: bool = False):
        if notes[0]["fields"].get("Front") == "synthetic-note-error-secret":
            raise ValueError("upstream error exposed synthetic-note-error-secret")
        return {"created": len(notes), "allowDuplicate": allowDuplicate}

    @backend.tool()
    def updateNoteFields(note: dict) -> str:
        return "updated"

    @backend.tool()
    def deleteNotes(notes: list[int]) -> str:
        return "deleted"

    @backend.tool()
    def sync() -> str:
        return "synced"

    @backend.tool()
    def retrieveMediaFile(filename: str) -> str:
        return "media"

    @backend.resource("anki://collection")
    def private_resource() -> str:
        return "resource"

    audit_path = tmp_path / "audit.jsonl"
    identity = {"claims": {"sub": "reader", "groups": ["anki-readers"]}}
    gateway = _gateway(identity, audit_path, tmp_path)
    upstream.mount(gateway, synthetic_backend=backend)

    async with Client(gateway) as client:
        assert {tool.name for tool in await client.list_tools()} == {
            "anki_listDecks",
            "anki_findNotes",
            "anki_notesInfo",
        }
        assert await client.list_resources() == []
        assert (await client.call_tool("anki_listDecks", {})).data == ["Fixture"]
        assert (await client.call_tool("anki_notesInfo", {"notes": [1]})).data[0]["fields"][
            "Front"
        ] == "private-study-text"
        for forbidden in (
            "anki_addNotes",
            "anki_updateNoteFields",
            "anki_deleteNotes",
            "anki_sync",
            "anki_retrieveMediaFile",
        ):
            with pytest.raises(ToolError, match="not authorized"):
                await client.call_tool(forbidden, {})

    identity["claims"] = {"sub": "operator", "groups": ["ops"]}
    async with Client(gateway) as client:
        assert {tool.name for tool in await client.list_tools()} == {"whoami"}
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("anki_listDecks", {})

    identity["claims"] = {"sub": "writer", "groups": ["anki-writers", "ops"]}
    async with Client(gateway) as client:
        assert {tool.name for tool in await client.list_tools()} == {
            "whoami",
            "anki_addNotes",
            "anki_updateNoteFields",
        }
        assert (await client.call_tool("whoami", {})).data == "kule-ok"
        result = await client.call_tool(
            "anki_addNotes",
            {
                "deckName": "Fixture",
                "modelName": "Basic",
                "notes": [{"fields": {"Front": "synthetic-note-secret"}}],
            },
        )
        assert result.data == {"created": 1, "allowDuplicate": False}
        with pytest.raises(ToolError, match="Anki upstream rejected the request"):
            await client.call_tool(
                "anki_addNotes",
                {
                    "deckName": "Fixture",
                    "modelName": "Basic",
                    "notes": [{"fields": {"Front": "synthetic-note-error-secret"}}],
                },
            )
        assert (await client.call_tool("whoami", {})).data == "kule-ok"
        for duplicate_override in (True, 1, "true", None):
            with pytest.raises(ToolError, match="duplicate creation is disabled"):
                await client.call_tool(
                    "anki_addNotes",
                    {
                        "deckName": "Fixture",
                        "modelName": "Basic",
                        "allowDuplicate": duplicate_override,
                        "notes": [{"fields": {"Front": "synthetic-note-secret"}}],
                    },
                )
        with pytest.raises(ToolError, match="media URL updates are disabled"):
            await client.call_tool(
                "anki_updateNoteFields",
                {
                    "note": {
                        "id": 1,
                        "fields": {"Front": "x"},
                        "picture": [{"url": "https://example.test"}],
                    }
                },
            )
        with pytest.raises(ToolError, match="batches must contain"):
            await client.call_tool(
                "anki_addNotes",
                {
                    "deckName": "Fixture",
                    "modelName": "Basic",
                    "notes": [{"fields": {"Front": str(i)}} for i in range(26)],
                },
            )

    assert verify(audit_path)[0]
    audit = audit_path.read_text()
    assert "synthetic-note-secret" not in audit
    assert "synthetic-note-error-secret" not in audit
    assert "private-study-text" not in audit
    records = [json.loads(line) for line in audit.splitlines()]
    calls = [record for record in records if record["event"] == "call"]
    assert all(
        "argument_count" in record["args"] for record in calls if record["tool"].startswith("anki_")
    )
    error_codes = {record["error_code"] for record in records if record["event"] == "error"}
    assert {
        "duplicates_disabled",
        "media_url_disabled",
        "batch_limit",
        "upstream_error",
    } <= error_codes


async def test_unavailable_anki_discovery_does_not_break_other_tools(tmp_path):
    class Unavailable(Middleware):
        async def on_list_tools(self, context, call_next):
            raise ConnectionError("synthetic upstream outage")

    backend = FastMCP("unavailable-anki", middleware=[Unavailable()])
    identity = {"claims": {"sub": "reader", "groups": ["ops", "anki-readers"]}}
    gateway = _gateway(identity, tmp_path / "audit.jsonl", tmp_path)
    upstream.mount(gateway, synthetic_backend=backend)

    async with Client(gateway) as client:
        assert {tool.name for tool in await client.list_tools()} == {"whoami"}
        assert (await client.call_tool("whoami", {})).data == "kule-ok"


async def test_unavailable_anki_call_does_not_break_other_tools(tmp_path):
    class UnavailableCall(Middleware):
        async def on_call_tool(self, context, call_next):
            raise ConnectionError("synthetic upstream outage")

    backend = FastMCP("unavailable-anki-call", middleware=[UnavailableCall()])

    @backend.tool()
    def listDecks() -> list[str]:
        return ["Fixture"]

    identity = {"claims": {"sub": "reader", "groups": ["ops", "anki-readers"]}}
    gateway = _gateway(identity, tmp_path / "audit.jsonl", tmp_path)
    upstream.mount(gateway, synthetic_backend=backend)

    async with Client(gateway) as client:
        assert {tool.name for tool in await client.list_tools()} == {
            "whoami",
            "anki_listDecks",
        }
        with pytest.raises(ToolError, match="Anki upstream is unavailable"):
            await client.call_tool("anki_listDecks", {})
        assert (await client.call_tool("whoami", {})).data == "kule-ok"
