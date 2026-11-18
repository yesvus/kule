"""Synthetic OpenHands Canvas management contract: no live Canvas or credentials."""

from __future__ import annotations

import json
from pathlib import Path

import httpx2
import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import AuthorizationError, ToolError
from helpers import OPERATOR, OUTSIDER

from operator_mcp.audit import AuditLog, verify
from operator_mcp.authz import Policy
from operator_mcp.middleware import OperatorMiddleware
from operator_mcp.server import build_server
from operator_mcp.tools import openhands

ORIGIN = "https://canvas.example.test:8000"
CONVERSATION = "11111111-1111-1111-1111-111111111111"
OTHER_CONVERSATION = "44444444-4444-4444-4444-444444444444"
LEGACY = "33333333-3333-3333-3333-333333333333"
PROFILE = "22222222-2222-2222-2222-222222222222"
REPOSITORY = "yesvus/kule"
OTHER_REPOSITORY = "other/repo"
READ_TOOLS = {
    "oh_list_conversations",
    "oh_get_conversation",
    "oh_get_conversation_runtime",
    "oh_search_events",
    "oh_get_event",
    "oh_list_agent_profiles",
}
OPERATE_TOOLS = {
    "oh_start_conversation",
    "oh_send_message",
    "oh_run_conversation",
    "oh_interrupt_conversation",
    "oh_pause_conversation",
    "oh_switch_acp_model",
}


def _assert_no_request(requests: list) -> None:
    assert requests == []


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    monkeypatch.setenv("KULE_OPENHANDS_WORKSPACE_ROOT", "/workspace/src")
    claims = {"value": OPERATOR}
    audit = tmp_path / "audit.jsonl"
    mcp = FastMCP(
        "kule-openhands-synthetic",
        middleware=[
            OperatorMiddleware(
                policy=Policy(required_group="ops", exec_group="exec", exec_enabled=False),
                audit=AuditLog(audit),
                kill_switch=tmp_path / "DISABLED",
                timeout_seconds=5,
                max_output_bytes=64 * 1024,
                claims_getter=lambda: claims["value"],
            )
        ],
    )
    return mcp, claims, audit


def test_pinned_fixture_and_endpoint_allowlist():
    spec = openhands._load_spec()
    assert spec["info"]["version"] == "1.62.0"
    assert not any("automation" in path for path in spec["paths"])

    restricted = openhands._restricted_spec()
    assert set(restricted["paths"]) == {endpoint.path for endpoint in openhands._ENDPOINTS.values()}
    assert all(len(operations) == 1 for operations in restricted["paths"].values())

    start = restricted["components"]["schemas"]["StartConversationRequest"]
    assert set(start["properties"]) == openhands._START_FIELDS - {"repository"}
    assert start["required"] == ["workspace", "agent_profile_id"]
    assert start["additionalProperties"] is False
    assert "agent_settings" not in start["properties"]
    assert "secrets" not in start["properties"]
    assert "hook_config" not in start["properties"]
    assert "tool_module_qualnames" not in start["properties"]

    message = restricted["components"]["schemas"]["SendMessageRequest"]
    assert set(message["properties"]) == {"content", "run"}
    assert message["properties"]["content"]["items"] == {"$ref": "#/components/schemas/TextContent"}


def test_text_message_validation_allows_an_omitted_run_flag():
    assert openhands._message_size({"content": [{"text": "hello"}]}) == 5
    assert openhands._message_size({"content": [{"text": "hello"}], "run": True}) == 5
    assert openhands._message_size({"content": [{"text": "hello"}], "run": None}) is None
    assert openhands._message_size({"content": [{"text": "x" * (32 * 1024 + 1)}]}) is None


def test_repository_scope_normalizes_and_rejects_non_canonical_names():
    assert openhands._repository("YesVus/Kule") == REPOSITORY
    for value in ("", "kule", "a/b/c", "../kule", "yesvus/..", "yesvus /kule"):
        with pytest.raises(AuthorizationError, match="repository target"):
            openhands._repository(value)


def test_fixed_https_origin_and_service_key_validation():
    assert openhands._origin("https://canvas.example.test:8000/") == ORIGIN
    for value in (
        "",
        "http://canvas.example.test:8000",
        "https://canvas.example.test/api",
        "https://user:pass@canvas.example.test",
        "https://canvas.example.test?x=1",
        "https://canvas.example.test#x",
        "https://canvas.example.test:bad",
        " https://canvas.example.test",
    ):
        with pytest.raises(RuntimeError, match="HTTPS origin"):
            openhands._origin(value)

    assert openhands._api_key("dedicated-service-key") == "dedicated-service-key"
    secret = "must-not-appear-in-an-error"
    for value in ("", f" {secret}", f"{secret}\n", f"{secret}\x00"):
        with pytest.raises(RuntimeError, match="missing or malformed") as err:
            openhands._api_key(value)
        assert secret not in str(err.value)

    assert openhands._workspace_root("/workspace/src/") == "/workspace/src"
    for value in ("", "workspace/src", "/", "/workspace\\src", "/workspace/\x00src"):
        with pytest.raises(RuntimeError):
            openhands._workspace_root(value)


async def test_tools_are_explicitly_allowlisted_and_tiered(gateway):
    mcp, _, _ = gateway
    async with httpx2.AsyncClient(
        base_url=ORIGIN,
        transport=httpx2.MockTransport(lambda request: httpx2.Response(200, json={})),
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            tools = {tool.name: tool for tool in await caller.list_tools()}
    assert set(tools) == READ_TOOLS | OPERATE_TOOLS
    for name in READ_TOOLS:
        assert tools[name].meta["fastmcp"]["tags"] == ["read"]
    for name in OPERATE_TOOLS:
        assert tools[name].meta["fastmcp"]["tags"] == ["operate"]
    assert not any("automation" in name for name in tools)
    assert await _list_resources_and_prompts(mcp) == ([], [])


async def _list_resources_and_prompts(mcp):
    async with Client(mcp) as caller:
        return await caller.list_resources(), await caller.list_prompts()


async def test_start_conversation_schema_hides_secrets_and_shell(gateway):
    mcp, _, _ = gateway
    async with httpx2.AsyncClient(
        base_url=ORIGIN,
        transport=httpx2.MockTransport(lambda request: httpx2.Response(200, json={})),
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            tools = {tool.name: tool for tool in await caller.list_tools()}
    start = tools["oh_start_conversation"].input_schema
    assert set(start["properties"]) == {
        "repository",
        "workspace",
        "worktree",
        "worktree_options",
        "initial_message",
        "agent_profile_id",
        "max_iterations",
        "max_budget_per_run",
        "tags",
        "autotitle",
    }
    assert start["required"] == ["workspace", "agent_profile_id", "repository"]
    assert "repository" in start["properties"]
    assert start["properties"]["workspace"]["additionalProperties"] is False
    assert set(start["properties"]["workspace"]["properties"]) == {"working_dir"}
    initial = start["properties"]["initial_message"]["anyOf"][0]
    assert set(initial["properties"]) == {"content", "run"}
    item = initial["properties"]["content"]["items"]
    assert item["title"] == "TextContent"
    assert set(item["properties"]) == {"cache_prompt", "type", "text"}
    assert item["properties"]["text"]["maxLength"] == 32 * 1024

    send = tools["oh_send_message"].input_schema
    assert set(send["properties"]) == {"repository", "conversation_id", "content", "run"}
    assert send["required"] == ["conversation_id", "content", "repository"]
    listed = tools["oh_list_conversations"].input_schema
    assert listed["required"] == ["repository"]
    assert "repository" in tools["oh_run_conversation"].input_schema["required"]


async def test_target_guard_and_unknown_arguments_never_reach_canvas(gateway):
    mcp, _, _ = gateway
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(200, json={"ok": True})

    start = {
        "repository": REPOSITORY,
        "workspace": {"working_dir": "/workspace/src/kule"},
        "agent_profile_id": PROFILE,
    }
    async with httpx2.AsyncClient(
        base_url=ORIGIN, transport=httpx2.MockTransport(handler)
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            for workspace in (
                {"working_dir": "/workspace/other"},
                {"working_dir": "/workspace/src/../etc"},
                {"working_dir": "/workspace/src/kule", "kind": "LocalWorkspace"},
            ):
                with pytest.raises(ToolError, match="workspace target"):
                    await caller.call_tool(
                        "oh_start_conversation", {**start, "workspace": workspace}
                    )
            for repository in ("not-a-repo", "a/b/c", "../repo"):
                with pytest.raises(ToolError, match="repository target"):
                    await caller.call_tool(
                        "oh_start_conversation", {**start, "repository": repository}
                    )
            with pytest.raises(ToolError, match="require worktree=true"):
                await caller.call_tool(
                    "oh_start_conversation",
                    {**start, "worktree_options": {"base": "head"}},
                )
            for options in (
                {"base": "evil"},
                {"base": "ref", "ref": "../../etc"},
                {"base": "ref"},
                {"base": "head", "branch_prefix": "oh23//"},
            ):
                with pytest.raises(ToolError, match="worktree options"):
                    await caller.call_tool(
                        "oh_start_conversation",
                        {**start, "worktree": True, "worktree_options": options},
                    )
            for field, value in (
                ("max_iterations", "many"),
                ("max_iterations", 5000),
                ("max_budget_per_run", -1),
                ("tags", {"Bad Key": "x"}),
                ("tags", {"ok": "x" * 257}),
                ("autotitle", "yes"),
            ):
                with pytest.raises(ToolError, match="not permitted"):
                    await caller.call_tool("oh_start_conversation", {**start, field: value})
            with pytest.raises(ToolError, match="repository tag"):
                await caller.call_tool(
                    "oh_start_conversation",
                    {**start, "tags": {"kulerepo": OTHER_REPOSITORY}},
                )
            with pytest.raises(ToolError, match="agent profile"):
                await caller.call_tool(
                    "oh_start_conversation",
                    {**start, "agent_profile_id": "not-a-uuid"},
                )
            with pytest.raises(ToolError, match="event target"):
                await caller.call_tool(
                    "oh_get_event",
                    {
                        "repository": REPOSITORY,
                        "conversation_id": CONVERSATION,
                        "event_id": "../../settings",
                    },
                )
            for forbidden in ("secrets", "hook_config", "agent_settings", "tool_module_qualnames"):
                with pytest.raises(ToolError, match="launch field is not permitted"):
                    await caller.call_tool("oh_start_conversation", {**start, forbidden: {}})
            with pytest.raises(ToolError, match="conversation scope is not permitted"):
                await caller.call_tool(
                    "oh_send_message",
                    {
                        "repository": REPOSITORY,
                        "conversation_id": CONVERSATION,
                        "content": [{"type": "text", "text": "hello"}],
                        "role": "system",
                    },
                )
            with pytest.raises(ToolError, match="message is not permitted"):
                await caller.call_tool(
                    "oh_send_message",
                    {
                        "repository": REPOSITORY,
                        "conversation_id": CONVERSATION,
                        "content": [{"type": "image", "text": "not text"}],
                    },
                )
            with pytest.raises(ToolError, match="conversation target"):
                await caller.call_tool(
                    "oh_send_message",
                    {
                        "repository": REPOSITORY,
                        "conversation_id": "not-a-uuid",
                        "content": [{"type": "text", "text": "hello"}],
                    },
                )
            with pytest.raises(ToolError, match="repository target"):
                await caller.call_tool(
                    "oh_send_message",
                    {
                        "conversation_id": CONVERSATION,
                        "content": [{"type": "text", "text": "hello"}],
                    },
                )
            with pytest.raises(ToolError, match="pagination"):
                await caller.call_tool(
                    "oh_list_conversations",
                    {"repository": REPOSITORY, "limit": 101},
                )
    _assert_no_request(requests)


async def test_management_calls_use_service_key_and_audit_prompt_digest(gateway):
    mcp, _, audit = gateway
    requests: list[httpx2.Request] = []
    prompt = "TOP-SECRET-PROMPT-that-must-not-be-audited"

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        if request.url.path == "/api/conversations/search":
            return httpx2.Response(
                200,
                json={
                    "items": [
                        {
                            "id": CONVERSATION,
                            "execution_status": "running",
                            "tags": {"kulerepo": REPOSITORY, "kuleissue": "yesvus/kule#23"},
                        },
                        {
                            "id": OTHER_CONVERSATION,
                            "execution_status": "running",
                            "tags": {"kulerepo": OTHER_REPOSITORY},
                        },
                        {"id": LEGACY, "execution_status": "finished"},
                    ],
                    "next_page_id": "next-page",
                },
            )
        if request.url.path == "/api/conversations":
            return httpx2.Response(200, json={"id": CONVERSATION, "execution_status": "idle"})
        if request.url.path == f"/api/conversations/{CONVERSATION}":
            return httpx2.Response(
                200,
                json={
                    "id": CONVERSATION,
                    "execution_status": "running",
                    "tags": {"kulerepo": REPOSITORY},
                },
            )
        return httpx2.Response(200, json={"ok": True})

    async with httpx2.AsyncClient(
        base_url=ORIGIN,
        headers={"X-Session-API-Key": "dedicated-service-key"},
        transport=httpx2.MockTransport(handler),
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            listed = await caller.call_tool(
                "oh_list_conversations", {"repository": REPOSITORY, "limit": 5}
            )
            assert [item["id"] for item in listed.data["items"]] == [CONVERSATION]
            assert listed.data["next_page_id"] == "next-page"
            started = await caller.call_tool(
                "oh_start_conversation",
                {
                    "repository": REPOSITORY,
                    "workspace": {"working_dir": "/workspace/src/kule"},
                    "worktree": True,
                    "worktree_options": {
                        "base": "default_branch",
                        "branch_prefix": "oh23/ws-oh-mcp/",
                    },
                    "agent_profile_id": PROFILE,
                    "tags": {"kuleissue": "yesvus/kule#23"},
                    "initial_message": {"content": [{"type": "text", "text": prompt}]},
                    "max_iterations": 100,
                },
            )
            assert started.data["id"] == CONVERSATION
            await caller.call_tool(
                "oh_send_message",
                {
                    "repository": REPOSITORY,
                    "conversation_id": CONVERSATION,
                    "content": [{"type": "text", "text": prompt}],
                    "run": True,
                },
            )
            await caller.call_tool(
                "oh_interrupt_conversation",
                {"repository": REPOSITORY, "conversation_id": CONVERSATION},
            )

    assert [(request.method, request.url.path) for request in requests] == [
        ("GET", "/api/conversations/search"),
        ("POST", "/api/conversations"),
        ("GET", f"/api/conversations/{CONVERSATION}"),
        ("POST", f"/api/conversations/{CONVERSATION}/events"),
        ("GET", f"/api/conversations/{CONVERSATION}"),
        ("POST", f"/api/conversations/{CONVERSATION}/interrupt"),
    ]
    assert all(
        request.headers["X-Session-API-Key"] == "dedicated-service-key" for request in requests
    )
    assert "repository" not in requests[0].url.params
    body = json.loads(requests[1].content)
    assert body == {
        "workspace": {"working_dir": "/workspace/src/kule"},
        "worktree": True,
        "worktree_options": {"base": "default_branch", "branch_prefix": "oh23/ws-oh-mcp/"},
        "initial_message": {"content": [{"type": "text", "text": prompt}]},
        "agent_profile_id": PROFILE,
        "tags": {"kuleissue": "yesvus/kule#23", "kulerepo": REPOSITORY},
        "max_iterations": 100,
    }

    raw = Path(audit).read_text()
    assert prompt not in raw
    assert verify(audit) == (True, 8)
    records = [json.loads(line) for line in raw.splitlines()]
    start = next(record for record in records if record.get("tool") == "oh_start_conversation")
    assert start["args"]["initial_message"]["valid"] is True
    assert start["args"]["initial_message"]["sha256"]
    assert start["args"]["working_dir"] == "/workspace/src/kule"


async def test_direct_id_actions_require_matching_native_repository_tag(gateway):
    mcp, _, _ = gateway
    requests: list[httpx2.Request] = []
    tags = {
        CONVERSATION: {"kulerepo": REPOSITORY},
        OTHER_CONVERSATION: {"kulerepo": OTHER_REPOSITORY},
        LEGACY: {},
    }

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        path = request.url.path
        if request.method == "GET" and path.startswith("/api/conversations/"):
            conversation_id = path.rsplit("/", 1)[-1]
            if conversation_id in tags:
                return httpx2.Response(
                    200, json={"id": conversation_id, "tags": tags[conversation_id]}
                )
        return httpx2.Response(200, json={"ok": True})

    async with httpx2.AsyncClient(
        base_url=ORIGIN, transport=httpx2.MockTransport(handler)
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            with pytest.raises(ToolError, match="outside the requested repository"):
                await caller.call_tool(
                    "oh_run_conversation",
                    {"repository": REPOSITORY, "conversation_id": OTHER_CONVERSATION},
                )
            with pytest.raises(ToolError, match="outside the requested repository"):
                await caller.call_tool(
                    "oh_get_conversation",
                    {"repository": REPOSITORY, "conversation_id": LEGACY},
                )
            with pytest.raises(ToolError, match="repository target"):
                await caller.call_tool("oh_run_conversation", {"conversation_id": CONVERSATION})
            assert (
                await caller.call_tool(
                    "oh_run_conversation",
                    {"repository": REPOSITORY, "conversation_id": CONVERSATION},
                )
            ).data == {"ok": True}

    assert [(request.method, request.url.path) for request in requests] == [
        ("GET", f"/api/conversations/{OTHER_CONVERSATION}"),
        ("GET", f"/api/conversations/{LEGACY}"),
        ("GET", f"/api/conversations/{CONVERSATION}"),
        ("POST", f"/api/conversations/{CONVERSATION}/run"),
    ]


def test_build_server_mounts_openhands_only_when_enabled(make_cfg, claims, monkeypatch):
    cfg = make_cfg()
    captured: dict[str, float] = {}

    def fake_mount(mcp, *, timeout_seconds: float) -> None:
        captured["timeout"] = timeout_seconds

    monkeypatch.setattr(openhands, "mount", fake_mount)
    build_server(cfg, claims_getter=claims)
    assert captured == {}
    monkeypatch.setenv("KULE_OPENHANDS_ENABLED", "1")
    build_server(cfg, claims_getter=claims)
    assert captured == {"timeout": cfg.tools.timeout_seconds}


async def test_outsider_sees_no_openhands_tools(gateway):
    mcp, claims, audit = gateway
    claims["value"] = OUTSIDER
    async with httpx2.AsyncClient(
        base_url=ORIGIN,
        transport=httpx2.MockTransport(lambda request: httpx2.Response(200, json={})),
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            assert await caller.list_tools() == []
            with pytest.raises(ToolError, match="not authorized"):
                await caller.call_tool("oh_list_conversations", {"repository": REPOSITORY})
    records = [json.loads(line) for line in Path(audit).read_text().splitlines()]
    assert records[-1]["event"] == "denied"
