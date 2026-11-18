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
SECOND_CONVERSATION = "55555555-5555-5555-5555-555555555555"
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
    "oh_rename_conversation",
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
    monkeypatch.setenv(
        "KULE_OPENHANDS_REPOSITORIES",
        json.dumps({REPOSITORY: "/workspace/src/kule"}),
    )
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
    assert sum(len(operations) for operations in restricted["paths"].values()) == len(
        openhands._ENDPOINTS
    )

    start = restricted["components"]["schemas"]["StartConversationRequest"]
    assert set(start["properties"]) == openhands._START_FIELDS - {"repository"}
    assert start["required"] == ["workspace", "agent_profile_id"]
    assert start["additionalProperties"] is False
    assert "agent_settings" not in start["properties"]
    assert "secrets" not in start["properties"]
    assert "hook_config" not in start["properties"]
    assert "tool_module_qualnames" not in start["properties"]

    update = restricted["components"]["schemas"]["UpdateConversationRequest"]
    assert set(update["properties"]) == {"title"}
    assert update["required"] == ["title"]
    assert update["additionalProperties"] is False

    message = restricted["components"]["schemas"]["SendMessageRequest"]
    assert set(message["properties"]) == {"content", "run"}
    assert message["properties"]["content"]["items"] == {"$ref": "#/components/schemas/TextContent"}


def test_text_message_validation_allows_an_omitted_run_flag():
    assert openhands._message_size({"content": [{"text": "hello"}]}) == 5
    assert openhands._message_size({"content": [{"text": "hello"}], "run": True}) == 5
    assert openhands._message_size({"content": [{"text": "hello"}], "run": None}) is None
    assert openhands._message_size({"content": [{"text": "x" * (32 * 1024 + 1)}]}) is None


def test_repository_scope_requires_an_approved_exact_mapping():
    approved = {REPOSITORY: "/workspace/src/kule"}
    assert openhands._repository("YesVus/Kule", approved) == REPOSITORY
    for value in (
        "",
        "kule",
        "a/b/c",
        "../kule",
        "yesvus/..",
        "yesvus /kule",
        "yesvus/other",
    ):
        with pytest.raises(AuthorizationError, match="repository target"):
            openhands._repository(value, approved)

    assert openhands._mapped_path("/workspace/src/kule") == "/workspace/src/kule"
    valid = json.dumps({REPOSITORY: "/workspace/src/kule"})
    assert openhands._repositories(valid) == {REPOSITORY: "/workspace/src/kule"}
    for raw in (
        "",
        "[]",
        "{}",
        json.dumps({REPOSITORY: "relative"}),
        json.dumps({REPOSITORY: "/"}),
        json.dumps({REPOSITORY: "/workspace/src/../etc"}),
        json.dumps({"bad": "/workspace/src/kule"}),
        json.dumps({REPOSITORY: "/workspace/src/kule", "other/repo": "/workspace/src/kule"}),
        json.dumps({REPOSITORY: "/workspace/src/kule", "YesVus/Kule": "/workspace/src/kule"}),
        '{"yesvus/kule":"/workspace/src/a","yesvus/kule":"/workspace/src/b"}',
    ):
        with pytest.raises(RuntimeError, match="KULE_OPENHANDS_REPOSITORIES"):
            openhands._repositories(raw)


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

    for value in ("", "workspace/src", "/", "/workspace\\src", "/workspace/\x00src"):
        with pytest.raises(RuntimeError, match="KULE_OPENHANDS_REPOSITORIES"):
            openhands._mapped_path(value)


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
    assert start["properties"]["max_budget_per_run"]["anyOf"][0]["maximum"] == 1000.0

    send = tools["oh_send_message"].input_schema
    assert set(send["properties"]) == {"repository", "conversation_id", "content", "run"}
    assert send["required"] == ["conversation_id", "content", "repository"]
    listed = tools["oh_list_conversations"].input_schema
    assert listed["required"] == ["repository"]
    assert listed["properties"]["page_id"]["maxLength"] == 256
    assert "Gateway continuation cursor" in listed["properties"]["page_id"]["description"]
    assert "repository" in tools["oh_run_conversation"].input_schema["required"]
    rename = tools["oh_rename_conversation"].input_schema
    assert set(rename["properties"]) == {"repository", "conversation_id", "title"}
    assert rename["required"] == ["conversation_id", "title", "repository"]
    assert "tags" not in rename["properties"]
    assert "max_budget_per_run" not in rename["properties"]


def test_budget_validation_rejects_non_finite_without_overflow():
    guard = openhands._TargetGuard(
        None,  # type: ignore[arg-type]
        {REPOSITORY: "/workspace/src/kule"},
        b"cursor-key",
    )
    base = {
        "repository": REPOSITORY,
        "workspace": {"working_dir": "/workspace/src/kule"},
        "agent_profile_id": PROFILE,
    }
    for budget in (float("inf"), float("nan"), 10**10000, -1, 0, 1000.01):
        with pytest.raises(AuthorizationError, match="budget"):
            guard._start({**base, "max_budget_per_run": budget})


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
                {"working_dir": "/workspace/src/kule/subdir"},
            ):
                with pytest.raises(ToolError, match="approved repository path"):
                    await caller.call_tool(
                        "oh_start_conversation", {**start, "workspace": workspace}
                    )
            with pytest.raises(ToolError, match="workspace target"):
                await caller.call_tool(
                    "oh_start_conversation",
                    {
                        **start,
                        "workspace": {
                            "working_dir": "/workspace/src/kule",
                            "kind": "LocalWorkspace",
                        },
                    },
                )
            for repository in ("not-a-repo", "a/b/c", "../repo", OTHER_REPOSITORY):
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
                {"base": ["head"]},
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
                ("max_budget_per_run", 10**10000),
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
            with pytest.raises(ToolError, match="repository target"):
                await caller.call_tool("oh_list_conversations", {"repository": OTHER_REPOSITORY})
            with pytest.raises(ToolError, match="repository target"):
                await caller.call_tool(
                    "oh_get_conversation",
                    {"repository": OTHER_REPOSITORY, "conversation_id": CONVERSATION},
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
            cursor = listed.data["next_page_id"]
            assert cursor.startswith("gc1.")
            assert "next-page" not in cursor
            assert OTHER_CONVERSATION not in cursor
            assert LEGACY not in cursor
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
            with pytest.raises(ToolError, match="outside the requested repository"):
                await caller.call_tool(
                    "oh_rename_conversation",
                    {
                        "repository": REPOSITORY,
                        "conversation_id": OTHER_CONVERSATION,
                        "title": "renamed",
                    },
                )
            with pytest.raises(ToolError, match="repository target"):
                await caller.call_tool("oh_run_conversation", {"conversation_id": CONVERSATION})
            assert (
                await caller.call_tool(
                    "oh_run_conversation",
                    {"repository": REPOSITORY, "conversation_id": CONVERSATION},
                )
            ).data == {"ok": True}
            assert (
                await caller.call_tool(
                    "oh_rename_conversation",
                    {
                        "repository": REPOSITORY,
                        "conversation_id": CONVERSATION,
                        "title": "renamed",
                    },
                )
            ).data == {"ok": True}

    assert [(request.method, request.url.path) for request in requests] == [
        ("GET", f"/api/conversations/{OTHER_CONVERSATION}"),
        ("GET", f"/api/conversations/{LEGACY}"),
        ("GET", f"/api/conversations/{OTHER_CONVERSATION}"),
        ("GET", f"/api/conversations/{CONVERSATION}"),
        ("POST", f"/api/conversations/{CONVERSATION}/run"),
        ("GET", f"/api/conversations/{CONVERSATION}"),
        ("PATCH", f"/api/conversations/{CONVERSATION}"),
    ]


def _full_conversation(conversation_id: str) -> dict:
    return {
        "id": conversation_id,
        "title": "session",
        "execution_status": "running",
        "tags": {"kulerepo": REPOSITORY, "kuleissue": "yesvus/kule#23"},
        "workspace": {
            "working_dir": "/workspace/src/kule",
            "kind": "RemoteWorkspace",
            "host": "https://runtime.example.test",
            "api_key": "REMOTE-SECRET",
        },
        "secret_registry": {"secret_sources": {"GH": {"value": "SECRET-REGISTRY"}}},
        "hook_config": {"pre_tool_use": [{"command": "HOOK-SECRET"}]},
        "agent_state": {"key": "AGENT-STATE-SECRET"},
        "agent": {"kind": "Agent", "llm": {"api_key": "LLM-SECRET"}},
        "tool_module_qualnames": {"bash": "SECRET.MODULE"},
        "blocked_actions": {"a": "BLOCKED-SECRET"},
        "runtime_info": {
            "runtime_status": "ready",
            "can_resume": True,
            "runtime_error": {"detail": "RUNTIME-SECRET"},
        },
        "launched_agent_profile": {
            "agent_profile_id": PROFILE,
            "secret_refs": ["SECRET-REF"],
        },
        "available_models": [
            {"model_id": "model", "name": "Model", "description": "desc", "extra": "MODEL-SECRET"}
        ],
        "metrics": {
            "model_name": "model",
            "accumulated_cost": 1.5,
            "max_budget_per_task": 10,
            "accumulated_token_usage": {},
            "extra": "METRIC-SECRET",
        },
    }


async def test_conversation_responses_are_projected_to_lifecycle_fields(gateway):
    mcp, _, _ = gateway

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/api/conversations/search":
            return httpx2.Response(
                200, json={"items": [_full_conversation(CONVERSATION)], "next_page_id": None}
            )
        if request.url.path in ("/api/conversations", f"/api/conversations/{CONVERSATION}"):
            return httpx2.Response(200, json=_full_conversation(CONVERSATION))
        return httpx2.Response(200, json={"ok": True})

    async with httpx2.AsyncClient(
        base_url=ORIGIN, transport=httpx2.MockTransport(handler)
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            fetched = await caller.call_tool(
                "oh_get_conversation",
                {"repository": REPOSITORY, "conversation_id": CONVERSATION},
            )
            listed = await caller.call_tool("oh_list_conversations", {"repository": REPOSITORY})
            started = await caller.call_tool(
                "oh_start_conversation",
                {
                    "repository": REPOSITORY,
                    "workspace": {"working_dir": "/workspace/src/kule"},
                    "agent_profile_id": PROFILE,
                },
            )

    for result in (fetched, listed.data["items"][0], started):
        data = result.data if hasattr(result, "data") else result
        if "items" in data:
            data = data["items"][0]
        assert data["workspace"] == {
            "working_dir": "/workspace/src/kule",
            "kind": "RemoteWorkspace",
        }
        assert data["agent_profile_id"] == PROFILE
        assert data["available_models"] == [
            {"model_id": "model", "name": "Model", "description": "desc"}
        ]
        assert set(data["metrics"]) == {
            "model_name",
            "accumulated_cost",
            "max_budget_per_task",
            "accumulated_token_usage",
        }
        rendered = json.dumps(data)
        for secret in (
            "REMOTE-SECRET",
            "SECRET-REGISTRY",
            "HOOK-SECRET",
            "AGENT-STATE-SECRET",
            "LLM-SECRET",
            "SECRET.MODULE",
            "BLOCKED-SECRET",
            "RUNTIME-SECRET",
            "SECRET-REF",
            "MODEL-SECRET",
            "METRIC-SECRET",
        ):
            assert secret not in rendered


async def test_listing_cursor_never_exposes_an_excluded_conversation(gateway):
    mcp, _, _ = gateway
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        if request.url.path == "/api/conversations/search":
            page = request.url.params.get("page_id")
            if page is None:
                return httpx2.Response(
                    200,
                    json={
                        "items": [{"id": CONVERSATION, "tags": {"kulerepo": REPOSITORY}}],
                        # Canvas points at an excluded conversation.
                        "next_page_id": OTHER_CONVERSATION,
                    },
                )
            assert page == CONVERSATION
            return httpx2.Response(
                200,
                json={
                    "items": [
                        {"id": CONVERSATION, "tags": {"kulerepo": REPOSITORY}},
                        {"id": SECOND_CONVERSATION, "tags": {"kulerepo": REPOSITORY}},
                    ],
                    "next_page_id": None,
                },
            )
        return httpx2.Response(200, json={"ok": True})

    async with httpx2.AsyncClient(
        base_url=ORIGIN, transport=httpx2.MockTransport(handler)
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            first = await caller.call_tool("oh_list_conversations", {"repository": REPOSITORY})
            cursor = first.data["next_page_id"]
            assert cursor.startswith("gc1.")
            assert OTHER_CONVERSATION not in cursor
            assert CONVERSATION not in cursor
            second = await caller.call_tool(
                "oh_list_conversations",
                {"repository": REPOSITORY, "page_id": cursor},
            )
            assert [item["id"] for item in second.data["items"]] == [SECOND_CONVERSATION]
            assert second.data["next_page_id"] is None
            with pytest.raises(ToolError, match="pagination is not permitted"):
                await caller.call_tool(
                    "oh_list_conversations",
                    {"repository": REPOSITORY, "page_id": cursor + "x"},
                )

    assert len(requests) == 2
    assert all("gc1." not in str(request.url) for request in requests)


async def test_stale_listing_cursor_fails_closed(gateway):
    mcp, _, _ = gateway

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/api/conversations/search":
            page = request.url.params.get("page_id")
            if page is None:
                items = [
                    {"id": CONVERSATION, "tags": {"kulerepo": REPOSITORY}},
                    {"id": OTHER_CONVERSATION, "tags": {"kulerepo": OTHER_REPOSITORY}},
                ]
            else:
                items = [{"id": SECOND_CONVERSATION, "tags": {"kulerepo": REPOSITORY}}]
            return httpx2.Response(200, json={"items": items, "next_page_id": None})
        return httpx2.Response(200, json={"ok": True})

    async with httpx2.AsyncClient(
        base_url=ORIGIN, transport=httpx2.MockTransport(handler)
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            first = await caller.call_tool("oh_list_conversations", {"repository": REPOSITORY})
            with pytest.raises(ToolError, match="cursor is stale"):
                await caller.call_tool(
                    "oh_list_conversations",
                    {"repository": REPOSITORY, "page_id": first.data["next_page_id"]},
                )


async def test_event_search_passes_bounded_filters_for_a_scoped_session(gateway):
    mcp, _, _ = gateway
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        if request.url.path == f"/api/conversations/{CONVERSATION}":
            return httpx2.Response(200, json={"id": CONVERSATION, "tags": {"kulerepo": REPOSITORY}})
        if request.url.path == f"/api/conversations/{CONVERSATION}/events/search":
            return httpx2.Response(200, json={"items": [], "next_page_id": None})
        return httpx2.Response(200, json={"ok": True})

    async with httpx2.AsyncClient(
        base_url=ORIGIN, transport=httpx2.MockTransport(handler)
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            await caller.call_tool(
                "oh_search_events",
                {
                    "repository": REPOSITORY,
                    "conversation_id": CONVERSATION,
                    "limit": 10,
                    "page_id": "event-page",
                    "kind": "MessageEvent",
                    "sort_order": "timestamp",
                },
            )
            with pytest.raises(ToolError, match="pagination is not permitted"):
                await caller.call_tool(
                    "oh_search_events",
                    {
                        "repository": REPOSITORY,
                        "conversation_id": CONVERSATION,
                        "limit": 101,
                    },
                )

    search = requests[1]
    assert search.url.params["limit"] == "10"
    assert search.url.params["page_id"] == "event-page"
    assert search.url.params["kind"] == "MessageEvent"
    assert search.url.params["sort_order"] == "timestamp"
    assert "repository" not in search.url.params


async def test_outbound_transport_strips_unapproved_headers():
    seen: dict[str, str] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.update(dict(request.headers))
        return httpx2.Response(200, json={})

    owned = openhands._client(ORIGIN, "dedicated-service-key", 20)
    assert isinstance(owned, openhands._ScopedClient)
    await owned.aclose()

    client = openhands._ScopedClient(
        base_url=ORIGIN,
        headers={"X-Session-API-Key": "dedicated-service-key"},
        transport=httpx2.MockTransport(handler),
    )
    try:
        await client.get(
            "/api/conversations/search",
            headers={
                "X-OpenHands-Observability-Tags": "repo=other",
                "Authorization": "Bearer operator",
                "Cookie": "session=operator",
            },
        )
    finally:
        await client.aclose()

    assert seen["x-session-api-key"] == "dedicated-service-key"
    for name in ("x-openhands-observability-tags", "authorization", "cookie"):
        assert name not in seen


async def test_lifespan_factory_is_callable_and_closes_the_owned_client():
    client = httpx2.AsyncClient(base_url=ORIGIN)
    lifespan = openhands._closing_lifespan(client)
    assert callable(lifespan)
    async with lifespan(FastMCP("lifespan-test")):
        assert client.is_closed is False
    assert client.is_closed is True


async def test_mount_uses_a_callable_lifespan_for_the_owned_client(monkeypatch):
    monkeypatch.setenv(
        "KULE_OPENHANDS_REPOSITORIES", json.dumps({REPOSITORY: "/workspace/src/kule"})
    )
    monkeypatch.setenv("KULE_OPENHANDS_API_URL", ORIGIN)
    monkeypatch.setenv("KULE_OPENHANDS_API_KEY", "dedicated-service-key")
    created: dict[str, httpx2.AsyncClient] = {}

    def fake_client(origin: str, key: str, timeout: float) -> httpx2.AsyncClient:
        client = openhands._ScopedClient(
            base_url=origin,
            headers={"X-Session-API-Key": key},
            transport=httpx2.MockTransport(lambda request: httpx2.Response(200, json={})),
        )
        created["client"] = client
        return client

    monkeypatch.setattr(openhands, "_client", fake_client)
    mcp = FastMCP("owned-lifespan")
    openhands.mount(mcp)
    async with Client(mcp) as caller:
        await caller.list_tools()
    assert created["client"].is_closed is True


def test_enabled_check_config_validates_canvas_settings(tmp_path, monkeypatch, capsys):
    from operator_mcp.cli import main

    config = tmp_path / "config.toml"
    config.write_text(
        """
[server]
public_url = "https://mcp.example.com"
[auth]
oidc_config_url = "https://id.example.com/.well-known/openid-configuration"
client_id = "client"
"""
    )
    monkeypatch.setenv("OPERATOR_MCP_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("OPERATOR_MCP_JWT_SIGNING_KEY", "k" * 32)
    monkeypatch.setenv("KULE_OPENHANDS_ENABLED", "1")
    for name in (
        "KULE_OPENHANDS_REPOSITORIES",
        "KULE_OPENHANDS_API_URL",
        "KULE_OPENHANDS_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    assert main(["check-config", "--config", str(config)]) == 2
    assert "KULE_OPENHANDS_REPOSITORIES" in capsys.readouterr().err

    monkeypatch.setenv(
        "KULE_OPENHANDS_REPOSITORIES", json.dumps({REPOSITORY: "/workspace/src/kule"})
    )
    monkeypatch.setenv("KULE_OPENHANDS_API_URL", ORIGIN)
    monkeypatch.setenv("KULE_OPENHANDS_API_KEY", "dedicated-service-key")
    assert main(["check-config", "--config", str(config)]) == 0
    assert "config ok" in capsys.readouterr().out

    monkeypatch.setenv("KULE_OPENHANDS_ENABLED", "0")
    for name in (
        "KULE_OPENHANDS_REPOSITORIES",
        "KULE_OPENHANDS_API_URL",
        "KULE_OPENHANDS_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    assert main(["check-config", "--config", str(config)]) == 0


def test_build_server_mounts_openhands_only_when_enabled(make_cfg, claims, monkeypatch):
    cfg = make_cfg()
    captured: dict[str, float] = {}
    monkeypatch.delenv("KULE_OPENHANDS_ENABLED", raising=False)

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
