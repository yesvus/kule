"""Synthetic OpenHands Canvas management contract: no live Canvas or credentials."""

from __future__ import annotations

import base64
import json
import ssl
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    "oh_switch_acp_effort",
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
    assert listed["properties"]["sort_order"]["enum"] == ["CREATED_AT", "CREATED_AT_DESC"]
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
                    "next_page_id": uuid.UUID(SECOND_CONVERSATION).hex,
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
            assert SECOND_CONVERSATION not in cursor
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


async def test_rate_limited_run_surfaces_the_fastmcp_retry_error(gateway):
    mcp, _, _ = gateway

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == f"/api/conversations/{CONVERSATION}":
            return httpx2.Response(200, json={"id": CONVERSATION, "tags": {"kulerepo": REPOSITORY}})
        if request.url.path == f"/api/conversations/{CONVERSATION}/events":
            return httpx2.Response(429, json={"detail": "too many requests"})
        return httpx2.Response(200, json={"ok": True})

    async with httpx2.AsyncClient(
        base_url=ORIGIN, transport=httpx2.MockTransport(handler)
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            with pytest.raises(ToolError, match="Rate limited by upstream API"):
                await caller.call_tool(
                    "oh_send_message",
                    {
                        "repository": REPOSITORY,
                        "conversation_id": CONVERSATION,
                        "content": [{"type": "text", "text": "start"}],
                        "run": True,
                    },
                )


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


async def test_effort_switch_is_scoped_and_validated(gateway):
    mcp, _, _ = gateway
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        if request.method == "GET":
            cid = request.url.path.rsplit("/", 1)[-1]
            repo = REPOSITORY if cid == CONVERSATION else OTHER_REPOSITORY
            return httpx2.Response(200, json={"id": cid, "tags": {"kulerepo": repo}})
        return httpx2.Response(200, json={"ok": True})

    args = {"repository": REPOSITORY, "conversation_id": CONVERSATION, "effort": "high"}
    async with httpx2.AsyncClient(
        base_url=ORIGIN, transport=httpx2.MockTransport(handler)
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            for invalid in ("bad effort", "", "a" * 65, "-high", ".high"):
                with pytest.raises(ToolError, match="effort identifier"):
                    await caller.call_tool("oh_switch_acp_effort", {**args, "effort": invalid})
                _assert_no_request(requests)
            with pytest.raises(ToolError, match="outside the requested repository"):
                await caller.call_tool(
                    "oh_switch_acp_effort", {**args, "conversation_id": OTHER_CONVERSATION}
                )
            result = await caller.call_tool("oh_switch_acp_effort", args)
            assert result.data == {"ok": True}

    assert [(request.method, request.url.path) for request in requests] == [
        ("GET", f"/api/conversations/{OTHER_CONVERSATION}"),
        ("GET", f"/api/conversations/{CONVERSATION}"),
        ("POST", f"/api/conversations/{CONVERSATION}/switch_acp_effort"),
    ]
    assert json.loads(requests[-1].content) == {"effort": "high"}
    assert openhands.audit_arguments("oh_switch_acp_effort", args)["effort"] == "high"


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
        "parent_conversation_id": "PARENT-CONVERSATION-SECRET",
        "sub_conversation_ids": ["CHILD-CONVERSATION-SECRET"],
        "forked_from_conversation_id": "FORK-CONVERSATION-SECRET",
        "forked_from_event_id": "FORK-EVENT-SECRET",
        "leaf_event_id": "LEAF-EVENT-SECRET",
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
            "PARENT-CONVERSATION-SECRET",
            "CHILD-CONVERSATION-SECRET",
            "FORK-CONVERSATION-SECRET",
            "FORK-EVENT-SECRET",
            "LEAF-EVENT-SECRET",
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
                        "next_page_id": uuid.UUID(OTHER_CONVERSATION).hex,
                    },
                )
            assert page == uuid.UUID(OTHER_CONVERSATION).hex
            return httpx2.Response(
                200,
                json={
                    "items": [
                        {"id": OTHER_CONVERSATION, "tags": {"kulerepo": OTHER_REPOSITORY}},
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
            with pytest.raises(ToolError, match="pagination is not permitted"):
                await caller.call_tool(
                    "oh_list_conversations",
                    {"repository": REPOSITORY, "page_id": "gc1." + "0" * 32 + ".\u00e9"},
                )

    assert len(requests) == 2
    assert all("gc1." not in str(request.url) for request in requests)


async def test_stale_listing_cursor_fails_closed(gateway):
    mcp, _, _ = gateway

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/api/conversations/search":
            page = request.url.params.get("page_id")
            if page is not None:
                assert page == uuid.UUID(page).hex
            if page is None:
                items = [{"id": CONVERSATION, "tags": {"kulerepo": REPOSITORY}}]
                next_page_id = uuid.UUID(SECOND_CONVERSATION).hex
            else:
                items = [{"id": CONVERSATION, "tags": {"kulerepo": REPOSITORY}}]
                next_page_id = None
            return httpx2.Response(200, json={"items": items, "next_page_id": next_page_id})
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


async def test_list_first_request_omits_null_status(gateway):
    mcp, _, _ = gateway
    seen: dict[str, str] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.update(dict(request.url.params))
        return httpx2.Response(200, json={"items": [], "next_page_id": None})

    async with httpx2.AsyncClient(
        base_url=ORIGIN, transport=httpx2.MockTransport(handler)
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            await caller.call_tool(
                "oh_list_conversations",
                {"repository": REPOSITORY, "status": None},
            )

    assert "status" not in seen


async def test_follow_up_list_requests_omit_null_filters():
    seen: dict[str, str] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.update(dict(request.url.params))
        return httpx2.Response(200, json={"items": [], "next_page_id": None})

    client = httpx2.AsyncClient(base_url=ORIGIN, transport=httpx2.MockTransport(handler))
    guard = openhands._TargetGuard(client, {REPOSITORY: "/workspace/src/kule"}, b"key")
    try:
        await guard._page(
            "abc123",
            {"status": None, "limit": 5, "sort_order": "CREATED_AT_DESC"},
        )
    finally:
        await client.aclose()

    assert "status" not in seen
    assert seen["limit"] == "5"
    assert seen["sort_order"] == "CREATED_AT_DESC"
    assert seen["page_id"] == "abc123"


async def test_list_guard_rejects_unstable_sort_order():
    guard = openhands._TargetGuard(
        None,  # type: ignore[arg-type]
        {REPOSITORY: "/workspace/src/kule"},
        b"key",
    )

    class _Message:
        name = "list_conversations"

        def __init__(self, arguments: dict) -> None:
            self.arguments = arguments

    class _Context:
        def __init__(self, message: _Message) -> None:
            self.message = message

    async def _unreachable(_context):
        raise AssertionError("the upstream request must not run")

    for sort_order in ("UPDATED_AT", ["CREATED_AT"], {"CREATED_AT": True}):
        with pytest.raises(AuthorizationError, match="sort order"):
            await guard.on_call_tool(
                _Context(_Message({"repository": REPOSITORY, "sort_order": sort_order})),
                _unreachable,
            )


def test_launch_checkout_is_bound_to_the_approved_repository_mapping():
    approved = {
        REPOSITORY: "/workspace/src/kule",
        OTHER_REPOSITORY: "/workspace/src/other",
    }
    guard = openhands._TargetGuard(None, approved, b"cursor-key")  # type: ignore[arg-type]
    base = {
        "repository": REPOSITORY,
        "agent_profile_id": PROFILE,
        "tags": {"kuleissue": "yesvus/kule#27"},
    }
    guard._start({**base, "workspace": {"working_dir": "/workspace/src/kule"}})
    for path in ("/workspace/src/other", "/workspace/src/kule-evil", "/workspace/src"):
        with pytest.raises(AuthorizationError, match="approved repository path"):
            guard._start({**base, "workspace": {"working_dir": path}})


async def test_truncated_listing_returns_a_resumable_opaque_cursor(gateway):
    mcp, _, _ = gateway
    excluded = [f"aaaaaaaa-aaaa-aaaa-aaaa-{index:012d}" for index in range(1, 7)]
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        page = request.url.params.get("page_id")
        if page is not None:
            assert page == uuid.UUID(page).hex
        page_id = str(uuid.UUID(page)) if page is not None else None
        if page_id is None:
            return httpx2.Response(
                200,
                json={
                    "items": [{"id": excluded[0]}],
                    "next_page_id": uuid.UUID(excluded[1]).hex,
                },
            )
        if page_id in excluded:
            index = excluded.index(page_id)
            if index < len(excluded) - 1:
                return httpx2.Response(
                    200,
                    json={
                        "items": [{"id": page_id}],
                        "next_page_id": uuid.UUID(excluded[index + 1]).hex,
                    },
                )
            return httpx2.Response(
                200,
                json={
                    "items": [
                        {"id": page_id},
                        {"id": CONVERSATION, "tags": {"kulerepo": REPOSITORY}},
                    ],
                    "next_page_id": None,
                },
            )
        raise AssertionError(f"unexpected page_id {page}")

    async with httpx2.AsyncClient(
        base_url=ORIGIN, transport=httpx2.MockTransport(handler)
    ) as client:
        openhands.mount(mcp, client=client)
        async with Client(mcp) as caller:
            first = await caller.call_tool("oh_list_conversations", {"repository": REPOSITORY})
            assert first.data["items"] == []
            assert first.data["truncated"] is True
            cursor = first.data["next_page_id"]
            assert cursor is not None and cursor.startswith("gc1.")
            payload = base64.urlsafe_b64decode(cursor.split(".", 2)[2] + "==")
            for conversation_id in excluded:
                assert conversation_id not in cursor
                assert conversation_id.encode("ascii") not in payload
                assert conversation_id.replace("-", "").encode("ascii") not in payload
                assert uuid.UUID(conversation_id).bytes not in payload
            second = await caller.call_tool(
                "oh_list_conversations",
                {"repository": REPOSITORY, "page_id": cursor},
            )
            assert [item["id"] for item in second.data["items"]] == [CONVERSATION]
            assert second.data["next_page_id"] is None
            assert "truncated" not in second.data

    assert len(requests) == 6


async def test_event_search_passes_bounded_filters_for_a_scoped_session(gateway):
    mcp, _, _ = gateway
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        if request.url.path == f"/api/conversations/{CONVERSATION}":
            return httpx2.Response(200, json={"id": CONVERSATION, "tags": {"kulerepo": REPOSITORY}})
        if request.url.path == f"/api/conversations/{CONVERSATION}/events/search":
            sort_order = request.url.params.get("sort_order")
            assert sort_order in (None, "TIMESTAMP", "TIMESTAMP_DESC")
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
                    "sort_order": "TIMESTAMP",
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
    assert search.url.params["sort_order"] == "TIMESTAMP"
    assert "repository" not in search.url.params


async def test_outbound_transport_strips_unapproved_headers_and_pins_the_configured_key():
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
        api_key="dedicated-service-key",
        transport=httpx2.MockTransport(handler),
    )
    try:
        await client.get(
            "/api/conversations/search",
            headers={
                "X-Session-API-Key": "caller-controlled-key",
                "X-OpenHands-Observability-Tags": "repo=other",
                "Authorization": "Bearer operator",
                "Cookie": "session=operator",
            },
        )
    finally:
        await client.aclose()

    # An inbound session key is filtered out and replaced with the configured key.
    assert seen["x-session-api-key"] == "dedicated-service-key"
    for name in ("x-openhands-observability-tags", "authorization", "cookie"):
        assert name not in seen


async def test_inbound_mcp_headers_cannot_override_the_canvas_key(gateway, monkeypatch):
    mcp, _, _ = gateway
    seen: dict[str, str] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.update(dict(request.headers))
        return httpx2.Response(200, json={"items": [], "next_page_id": None})

    client = openhands._ScopedClient(
        base_url=ORIGIN,
        api_key="dedicated-service-key",
        transport=httpx2.MockTransport(handler),
    )
    # Simulate FastMCP copying inbound MCP HTTP headers onto the built request.
    monkeypatch.setattr(
        "fastmcp.server.providers.openapi.components.get_http_headers",
        lambda: {
            "X-Session-API-Key": "caller-controlled-key",
            "X-OpenHands-Observability-Tags": "repo=other",
        },
    )
    openhands.mount(mcp, client=client)
    async with Client(mcp) as caller:
        await caller.call_tool("oh_list_conversations", {"repository": REPOSITORY})

    assert seen["x-session-api-key"] == "dedicated-service-key"
    assert "x-openhands-observability-tags" not in seen


async def test_scoped_client_rebuilds_body_framing_for_a_real_connection():
    seen: dict[str, object] = {}

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            seen["headers"] = dict(self.headers)
            seen["body"] = self.rfile.read(length)
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = openhands._ScopedClient(
        base_url=f"http://127.0.0.1:{server.server_address[1]}",
        api_key="dedicated-service-key",
        timeout=5,
    )
    try:
        response = await client.post(
            "/api/conversations",
            json={"title": "session"},
            headers={
                "Host": "caller.example.test",
                "Content-Length": "999",
                "Transfer-Encoding": "chunked",
                "X-Session-API-Key": "caller-controlled-key",
            },
        )
    finally:
        await client.aclose()
        server.shutdown()
        server.server_close()

    assert response.status_code == 200
    headers = seen["headers"]
    assert headers["Host"] == f"127.0.0.1:{server.server_address[1]}"
    assert headers["Content-Length"] == str(len(seen["body"]))
    assert "Transfer-Encoding" not in headers
    assert headers["X-Session-API-Key"] == "dedicated-service-key"
    assert seen["body"] == b'{"title":"session"}'


async def test_lifespan_factory_is_callable_and_closes_the_owned_client():
    client = httpx2.AsyncClient(base_url=ORIGIN)
    lifespan = openhands._closing_lifespan(client)
    assert callable(lifespan)
    async with lifespan(FastMCP("lifespan-test")):
        assert client.is_closed is False
    assert client.is_closed is True


@pytest.mark.parametrize("explicit_ca", [False, True])
async def test_mount_uses_a_callable_lifespan_for_the_owned_client(monkeypatch, explicit_ca):
    import certifi

    monkeypatch.setenv(
        "KULE_OPENHANDS_REPOSITORIES", json.dumps({REPOSITORY: "/workspace/src/kule"})
    )
    monkeypatch.setenv("KULE_OPENHANDS_API_URL", ORIGIN)
    monkeypatch.setenv("KULE_OPENHANDS_API_KEY", "dedicated-service-key")
    monkeypatch.delenv("KULE_OPENHANDS_CA_FILE", raising=False)
    if explicit_ca:
        monkeypatch.setenv("KULE_OPENHANDS_CA_FILE", certifi.where())
    created: dict[str, httpx2.AsyncClient] = {}

    def fake_client(
        origin: str, key: str, timeout: float, *, verify: bool | ssl.SSLContext
    ) -> httpx2.AsyncClient:
        if explicit_ca:
            assert isinstance(verify, ssl.SSLContext)
            assert verify.verify_mode == ssl.CERT_REQUIRED
            assert verify.check_hostname
        else:
            assert verify is True
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


def test_explicit_canvas_ca_bundle_is_validated(tmp_path, monkeypatch):
    import certifi

    ca_file = Path(certifi.where())
    context = openhands._tls_verify({"KULE_OPENHANDS_CA_FILE": str(ca_file)})
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.cert_store_stats()["x509_ca"] > 0
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ambient-ca.pem")
    assert openhands._tls_verify({}) is True
    invalid = tmp_path / "invalid.pem"
    invalid.write_text("not a certificate", encoding="utf-8")
    for raw in ("", "relative.pem", str(tmp_path / "missing.pem"), str(invalid)):
        with pytest.raises(RuntimeError, match="KULE_OPENHANDS_CA_FILE"):
            openhands._tls_verify({"KULE_OPENHANDS_CA_FILE": raw})


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

    monkeypatch.setenv("KULE_OPENHANDS_CA_FILE", str(tmp_path / "missing.pem"))
    assert main(["check-config", "--config", str(config)]) == 2
    assert "KULE_OPENHANDS_CA_FILE" in capsys.readouterr().err

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


def test_cluster_http_origin_opt_in_and_strict_host_allowlist():
    for blocked in (
        "http://canvas.openhands.svc.cluster.local:8000",
        "http://127.0.0.1:8000",
    ):
        with pytest.raises(RuntimeError, match="HTTPS origin"):
            openhands._origin(blocked)

    for allowed, expected in (
        (
            "http://canvas.openhands.svc.cluster.local:8000/",
            "http://canvas.openhands.svc.cluster.local:8000",
        ),
        ("http://canvas.openhands.svc:8000", "http://canvas.openhands.svc:8000"),
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
        ("http://localhost:8000", "http://localhost:8000"),
        ("http://[::1]:8000", "http://[::1]:8000"),
        ("https://canvas.example.test:8000", "https://canvas.example.test:8000"),
    ):
        assert openhands._origin(allowed, allow_cluster_http=True) == expected

    for unsafe in (
        "http://canvas.example.test:8000",
        "http://192.0.2.10:8000",
        "http://svc.cluster.local:8000",
        "http://canvas.svc.cluster.local:8000",
        "http://a.b.c.svc.cluster.local:8000",
        "http://canvas.openhands.svc.cluster.local.attacker.example:8000",
        "http://canvas.openhands.svc.cluster.local.:8000",
        "http://-bad.openhands.svc.cluster.local:8000",
        "http://canvas.openhands.svc.cluster.local/api",
        "http://user:pass@canvas.openhands.svc.cluster.local:8000",
    ):
        with pytest.raises(RuntimeError, match="cluster-local HTTP"):
            openhands._origin(unsafe, allow_cluster_http=True)


def test_cluster_http_optional_api_key_and_ca_rejection(tmp_path, monkeypatch, capsys):
    import certifi

    from operator_mcp.cli import main

    repos = json.dumps({REPOSITORY: "/workspace/src/kule"})
    cluster_origin = "http://canvas.openhands.svc.cluster.local:8000"
    base_env = {
        "KULE_OPENHANDS_REPOSITORIES": repos,
        "KULE_OPENHANDS_ALLOW_CLUSTER_HTTP": "1",
        "KULE_OPENHANDS_API_URL": cluster_origin,
    }
    assert openhands.settings_from_env(base_env) == (
        {REPOSITORY: "/workspace/src/kule"},
        cluster_origin,
        None,
    )
    assert openhands.settings_from_env(
        {**base_env, "KULE_OPENHANDS_API_KEY": "dedicated-service-key"}
    ) == (
        {REPOSITORY: "/workspace/src/kule"},
        cluster_origin,
        "dedicated-service-key",
    )

    secret = "must-not-appear-in-an-error"
    for bad_key in (f" {secret}", f"{secret}\n"):
        with pytest.raises(RuntimeError, match="missing or malformed") as err:
            openhands.settings_from_env({**base_env, "KULE_OPENHANDS_API_KEY": bad_key})
        assert secret not in str(err.value)

    with pytest.raises(RuntimeError, match="missing or malformed"):
        openhands.settings_from_env(
            {
                "KULE_OPENHANDS_REPOSITORIES": repos,
                "KULE_OPENHANDS_ALLOW_CLUSTER_HTTP": "1",
                "KULE_OPENHANDS_API_URL": ORIGIN,
            }
        )

    with pytest.raises(RuntimeError, match="KULE_OPENHANDS_CA_FILE requires an HTTPS origin"):
        openhands.validate_settings({**base_env, "KULE_OPENHANDS_CA_FILE": certifi.where()})

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
    monkeypatch.setenv("KULE_OPENHANDS_ALLOW_CLUSTER_HTTP", "1")
    monkeypatch.setenv("KULE_OPENHANDS_REPOSITORIES", repos)
    monkeypatch.setenv("KULE_OPENHANDS_API_URL", cluster_origin)
    monkeypatch.delenv("KULE_OPENHANDS_API_KEY", raising=False)
    monkeypatch.delenv("KULE_OPENHANDS_CA_FILE", raising=False)
    assert main(["check-config", "--config", str(config)]) == 0
    assert "config ok" in capsys.readouterr().out


async def test_cluster_http_mount_omits_api_key_strips_inbound_key_and_supports_cursors(
    gateway, monkeypatch
):
    from urllib.parse import parse_qs, urlsplit

    mcp, _, _ = gateway
    seen_headers: list[dict[str, str]] = []

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            seen_headers.append({k.lower(): v for k, v in self.headers.items()})
            parsed = urlsplit(self.path)
            if parsed.path == "/api/agent-profiles":
                payload = {"profiles": [{"id": PROFILE, "name": "default"}]}
            elif parsed.path == "/api/conversations/search":
                page = parse_qs(parsed.query).get("page_id", [None])[0]
                if page is None:
                    payload = {
                        "items": [{"id": CONVERSATION, "tags": {"kulerepo": REPOSITORY}}],
                        "next_page_id": SECOND_CONVERSATION,
                    }
                elif page == uuid.UUID(SECOND_CONVERSATION).hex:
                    payload = {
                        "items": [{"id": SECOND_CONVERSATION, "tags": {"kulerepo": REPOSITORY}}],
                        "next_page_id": None,
                    }
                else:
                    payload = {"items": [], "next_page_id": None}
            else:
                payload = {"ok": True}
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    monkeypatch.setenv("KULE_OPENHANDS_ALLOW_CLUSTER_HTTP", "1")
    monkeypatch.setenv("KULE_OPENHANDS_API_URL", origin)
    monkeypatch.delenv("KULE_OPENHANDS_API_KEY", raising=False)
    monkeypatch.delenv("KULE_OPENHANDS_CA_FILE", raising=False)
    try:
        openhands.mount(mcp)
        async with Client(mcp) as caller:
            profiles = await caller.call_tool("oh_list_agent_profiles", {})
            assert profiles.data == {"profiles": [{"id": PROFILE, "name": "default"}]}

            page1 = await caller.call_tool("oh_list_conversations", {"repository": REPOSITORY})
            assert [item["id"] for item in page1.data["items"]] == [CONVERSATION]
            cursor = page1.data["next_page_id"]
            assert isinstance(cursor, str) and cursor.startswith("gc1.")

            page2 = await caller.call_tool(
                "oh_list_conversations", {"repository": REPOSITORY, "page_id": cursor}
            )
            assert [item["id"] for item in page2.data["items"]] == [SECOND_CONVERSATION]
            assert page2.data["next_page_id"] is None

        async with openhands._ScopedClient(base_url=origin, api_key=None, timeout=5) as scoped:
            response = await scoped.get(
                "/api/agent-profiles",
                headers={"X-Session-API-Key": "caller-controlled-key"},
            )
            assert response.status_code == 200
    finally:
        server.shutdown()
        server.server_close()

    assert len(seen_headers) == 4
    assert all("x-session-api-key" not in headers for headers in seen_headers)
