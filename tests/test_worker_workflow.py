"""Source-only worker contract tests. No OpenHands server, cluster or secrets."""

from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs
from uuid import UUID, uuid4

import httpx2
import pytest

from operator_mcp import worker_workflow as ww
from operator_mcp.worker_workflow import (
    DEFAULT_MODEL,
    WorkerClient,
    WorkerError,
    WorkerRunPending,
    WorkerTask,
    WorkerTimeout,
    build_prompt,
    build_start_request,
    build_task_message,
    map_status,
    parse_pr_evidence,
    validate_model,
)

PROFILE_ID = UUID("11111111-1111-4111-8111-111111111111")
CONVERSATION_ID = UUID("22222222-2222-4222-8222-222222222222")
COMMIT = "a" * 40
REPO_PATH = "/workspace/src/kule"
REPOSITORIES = {"yesvus/kule": REPO_PATH}
ISSUE = "yesvus/kule#23"
PROFILE_NAME = "opencode-economical"
OTHER_MODEL = "opencode-go/deepseek-v4-pro"


def task(**overrides) -> WorkerTask:
    values = {
        "issue_ref": ISSUE,
        "repository": "yesvus/kule",
        "task": "Implement the source-only worker workflow.",
        "profile_id": PROFILE_ID,
        "expected_model": DEFAULT_MODEL,
        "branch_prefix": "oh23/ws-oh-workers/",
        "conversation_id": CONVERSATION_ID,
        "max_budget_per_run": 2.0,
    }
    values.update(overrides)
    return WorkerTask(**values)


def worktree(task_value: WorkerTask) -> str:
    return f"/tmp/conversation-worktrees/{task_value.conversation_id}/kule"


def profile(task_value: WorkerTask, **overrides) -> dict:
    payload = {
        "id": str(task_value.profile_id),
        "name": PROFILE_NAME,
        "agent_kind": "acp",
        "acp_server": task_value.expected_acp_server,
        "acp_model": task_value.expected_model,
        "acp_effort": None,
        "acp_command": None,
        "acp_args": None,
        "secret_refs": None,
        "mcp_server_refs": None,
    }
    payload.update(overrides)
    return payload


def conversation(task_value: WorkerTask, **overrides) -> dict:
    payload = {
        "id": str(task_value.conversation_id),
        "execution_status": "running",
        "current_model_id": task_value.expected_model,
        "current_effort": task_value.expected_effort,
        "title": "source-only worker",
        "tags": dict(task_value.tags),
        "workspace": {"kind": "LocalWorkspace", "working_dir": worktree(task_value)},
        "agent": {
            "kind": "ACPAgent",
            "acp_server": task_value.expected_acp_server,
            "acp_model": task_value.expected_model,
        },
    }
    payload.update(overrides)
    return payload


def evidence_block(task_value: WorkerTask, **overrides) -> str:
    payload = {
        "pr_url": f"https://github.com/{task_value.repository}/pull/42",
        "branch": task_value.branch,
        "commit": COMMIT,
        "tests": ["pytest -q tests/test_worker_workflow.py: passed"],
        "blockers": [],
    }
    payload.update(overrides)
    return f"Report.\n\n```worker-evidence\n{json.dumps(payload)}\n```\n"


class Server:
    """Small scripted OpenHands transport with call recording."""

    def __init__(
        self,
        task_value: WorkerTask,
        *,
        profile_model: str | None = None,
        repositories: dict[str, str] | None = None,
    ) -> None:
        self.task = task_value
        self.repositories = repositories or dict(REPOSITORIES)
        self.calls: list[tuple[str, str, dict | None, str]] = []
        self.start_status = 201
        self.auto_start = False
        self.created = False
        self.echo_tags = True
        self.tags_by_id: dict[str, dict] = {}
        self.profile = profile(
            task_value,
            acp_model=task_value.expected_model if profile_model is None else profile_model,
        )
        self.conversation = conversation(task_value)
        self.final = evidence_block(task_value)
        self.catalog = [
            {"model_id": task_value.expected_model, "name": "requested"},
            {"model_id": OTHER_MODEL, "name": "default"},
        ]
        self.efforts = {
            task_value.expected_model: [
                {"value": "high", "name": "High"},
                {"value": "max", "name": "Max"},
            ]
        }
        self.discovery_error: dict | None = None
        self.pr = {
            "url": f"https://github.com/{task_value.repository}/pull/42",
            "head_sha": COMMIT,
            "head_ref": task_value.branch,
            "state": "open",
            "checks": "success",
            "draft": False,
        }
        self.start_delay = 0.0
        self.active_starts = 0
        self.max_active_starts = 0
        self.workspace_override: dict | None = None
        self.event_status = 200
        self.run_status = 200
        self.final_status = 200
        self.task_accepted = True
        # Statuses returned by successive single-conversation GETs.
        self.get_status_script: list[str] = []
        self.search_pages: list[dict] = [
            {"items": [conversation(task_value)], "next_page_id": None}
        ]

    def info_for(self, conversation_id: str) -> dict:
        return {
            **self.conversation,
            "id": conversation_id,
            "tags": self.tags_by_id.get(conversation_id, self.conversation.get("tags", {})),
            "workspace": self.workspace_override
            or {
                "kind": "LocalWorkspace",
                "working_dir": f"/tmp/conversation-worktrees/{conversation_id}/kule",
            },
        }

    async def handler(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content) if request.content else None
        query = request.url.query.decode()
        self.calls.append((request.method, request.url.path, body, query))
        path = request.url.path
        if request.method == "GET" and path == "/api/agent-profiles":
            return httpx2.Response(
                200,
                json={
                    "profiles": [
                        {
                            "id": str(self.task.profile_id),
                            "name": self.profile["name"],
                            "agent_kind": self.profile["agent_kind"],
                        }
                    ],
                    "active_agent_profile_id": None,
                },
            )
        if request.method == "GET" and path == f"/api/agent-profiles/{self.profile['name']}":
            return httpx2.Response(
                200, json={"name": self.profile["name"], "profile": self.profile}
            )
        if request.method == "POST" and path == "/api/acp/models":
            return httpx2.Response(
                200,
                json={
                    "current_model_id": OTHER_MODEL,
                    "available_models": self.catalog,
                    "efforts_by_model": self.efforts,
                    "error": self.discovery_error,
                },
            )
        if (
            request.method == "GET"
            and path.startswith("/api/conversations/")
            and path.endswith("/events/search")
        ):
            return httpx2.Response(
                200,
                json={
                    "items": [{"kind": "MessageEvent"}] if self.task_accepted else [],
                    "next_page_id": None,
                },
            )
        if request.method == "GET" and path == "/api/conversations/search":
            params = parse_qs(query)
            page = int(params.get("page_id", ["0"])[0])
            return httpx2.Response(200, json=self.search_pages[page])
        if request.method == "POST" and path == "/api/conversations":
            self.active_starts += 1
            self.max_active_starts = max(self.max_active_starts, self.active_starts)
            if self.start_delay:
                await asyncio.sleep(self.start_delay)
            self.active_starts -= 1
            conversation_id = body["conversation_id"]
            if self.auto_start:
                status = 200 if self.created else 201
                self.created = True
            else:
                status = self.start_status
            if self.echo_tags and isinstance(body.get("tags"), dict):
                self.tags_by_id[conversation_id] = body["tags"]
            info = self.info_for(conversation_id)
            return httpx2.Response(status, json=info)
        if path.startswith("/api/conversations/") and request.method == "POST":
            parts = path.strip("/").split("/")
            # /api/conversations/{id}/{action}
            if len(parts) == 4 and parts[3] == "switch_acp_model":
                self.conversation = {
                    **self.conversation,
                    "current_model_id": body["model"],
                }
                return httpx2.Response(200, json={"success": True})
            if len(parts) == 4 and parts[3] == "switch_acp_effort":
                self.conversation = {
                    **self.conversation,
                    "current_effort": body["effort"],
                }
                return httpx2.Response(200, json={"success": True})
            if len(parts) == 4 and parts[3] == "events":
                # A saved message is accepted even when no run slot is
                # available (HTTP 429).
                self.task_accepted = True
                if self.event_status == 200:
                    self.conversation = {
                        **self.conversation,
                        "execution_status": "running",
                    }
                return httpx2.Response(self.event_status, json={"success": True})
            if len(parts) == 4 and parts[3] == "run":
                if self.run_status == 200:
                    self.conversation = {
                        **self.conversation,
                        "execution_status": "running",
                    }
                return httpx2.Response(self.run_status, json={"success": True})
            if len(parts) == 4 and parts[3] == "interrupt":
                if self.conversation.get("execution_status") not in {
                    "finished",
                    "error",
                    "stuck",
                }:
                    self.conversation = {
                        **self.conversation,
                        "execution_status": "paused",
                    }
                return httpx2.Response(200, json={"success": True})
        if (
            request.method == "GET"
            and path.startswith("/api/conversations/")
            and path.count("/") == 3
        ):
            conversation_id = path.rsplit("/", 1)[-1]
            if self.get_status_script:
                self.conversation = {
                    **self.conversation,
                    "execution_status": self.get_status_script.pop(0),
                }
            return httpx2.Response(200, json=self.info_for(conversation_id))
        if (
            request.method == "GET"
            and path.startswith("/api/conversations/")
            and path.endswith("/agent_final_response")
        ):
            if self.final_status != 200:
                return httpx2.Response(self.final_status, json={"detail": "failed"})
            return httpx2.Response(200, json={"response": self.final})
        if (
            request.method == "GET"
            and path == f"/api/git/repositories/{self.task.repository}/pull-requests/42"
        ):
            return httpx2.Response(200, json=self.pr)
        return httpx2.Response(404, json={"detail": "not found"})

    def methods(self) -> list[str]:
        return [method for method, _, _, _ in self.calls]


def client_for(server: Server, **kwargs) -> WorkerClient:
    return WorkerClient(
        "https://canvas.example",
        "synthetic-session-key",
        repositories=server.repositories,
        transport=httpx2.MockTransport(server.handler),
        **kwargs,
    )


def test_exact_model_validation_rejects_display_name_and_globs():
    assert validate_model(DEFAULT_MODEL) == "opencode-go/deepseek-v4.1-flash"
    assert "1017" not in DEFAULT_MODEL
    for bad in (
        " opencode-go/deepseek-v4.1-flash",
        "opencode-go/*",
        "opencode-go/deepseek-v4.1-flash?",
        "",
        "opencode-go/../deepseek-v4.1-flash",
    ):
        with pytest.raises(WorkerError):
            validate_model(bad)
    wrong = task(expected_model="opencode-go/deepseek-v4.1-flash-1017")
    assert wrong.expected_model != DEFAULT_MODEL


def test_task_requires_matching_issue_repo_and_canonical_identity():
    value = task()
    assert value.repository_key == "yesvus/kule"
    assert value.tags == {
        "kulerepo": "yesvus/kule",
        "kuleissue": ISSUE,
        "kuletask": value.task_digest,
        "kulemodel": DEFAULT_MODEL,
        "kuleprofile": str(PROFILE_ID),
        "kulebranch": value.branch,
        "kuleeffort": "-",
    }
    with pytest.raises(WorkerError, match="issue_ref repository"):
        task(issue_ref="yesvus/ops#23")
    with pytest.raises(WorkerError, match="repository"):
        task(repository="not-a-repo")
    with pytest.raises(WorkerError, match="issue_ref"):
        task(repository="../kule", issue_ref="../kule#1")
    with pytest.raises(WorkerError, match="repository"):
        task(repository="../kule")
    with pytest.raises(WorkerError, match="repository"):
        task(repository="yesvus/..")
    with pytest.raises(WorkerError, match="repository"):
        ww._canonical_repo("yesvus/..")
    with pytest.raises(WorkerError, match="conversation_id"):
        task(conversation_id="../../etc/passwd")
    with pytest.raises(WorkerError, match="branch_prefix"):
        task(branch_prefix="../escape/")
    with pytest.raises(WorkerError, match="branch_prefix"):
        task(branch_prefix="oh23//worker/")
    with pytest.raises(WorkerError, match="branch_prefix"):
        task(branch_prefix="oh23/.lock/")
    with pytest.raises(WorkerError, match="branch_prefix"):
        task(branch_prefix="openhands/.worker/")
    with pytest.raises(WorkerError, match="branch_prefix"):
        task(branch_prefix="openhands/release..candidate/")
    with pytest.raises(WorkerError, match="secret values"):
        task(secrets={"name": "not-an-object"})


@pytest.mark.parametrize(
    "repository",
    ["./kule", "../kule", "yesvus/.", "yesvus/..", ".", "..", "yesvus/../other"],
)
def test_repository_rejects_dot_and_dotdot_components(repository):
    with pytest.raises(WorkerError, match="repository"):
        ww._canonical_repo(repository)
    with pytest.raises(WorkerError, match="repository"):
        task(repository=repository, issue_ref=f"{repository}#1")


def test_start_request_in_profile_mode_has_no_initial_message():
    value = task()
    pre = ww.ModelPreflight(
        profile_name=PROFILE_NAME,
        profile_id=PROFILE_ID,
        mode="profile",
        acp_server="opencode",
        model=DEFAULT_MODEL,
    )
    body = build_start_request(value, REPO_PATH, pre)
    assert body["workspace"] == {"kind": "LocalWorkspace", "working_dir": REPO_PATH}
    assert body["worktree"] is True
    assert body["worktree_options"] == {
        "base": "default_branch",
        "branch_prefix": "oh23/ws-oh-workers/",
    }
    assert body["agent_profile_id"] == str(PROFILE_ID)
    assert "agent_settings" not in body
    assert "initial_message" not in body
    assert body["tags"] == value.tags
    message = build_task_message(value)
    assert message["run"] is True
    assert "worker-evidence" in message["content"][0]["text"]
    assert value.branch in message["content"][0]["text"]


def test_start_request_in_override_mode_uses_agent_settings_and_filters_secrets():
    value = task(
        secrets={
            "OPENCODE_API_KEY": {"kind": "LookupSecret", "url": "x"},
            "UNRELATED": {"kind": "StaticSecret", "value": "y"},
        }
    )
    pre = ww.ModelPreflight(
        profile_name=PROFILE_NAME,
        profile_id=PROFILE_ID,
        mode="override",
        acp_server="opencode",
        model=DEFAULT_MODEL,
        agent_settings={
            "agent_kind": "acp",
            "acp_server": "opencode",
            "acp_model": DEFAULT_MODEL,
        },
        secret_names=("OPENCODE_API_KEY",),
    )
    body = build_start_request(value, REPO_PATH, pre)
    assert "agent_profile_id" not in body
    assert body["agent_settings"]["acp_model"] == DEFAULT_MODEL
    assert set(body["secrets"]) == {"OPENCODE_API_KEY"}


async def test_preflight_uses_profile_when_model_and_effort_match():
    value = task()
    server = Server(value)
    async with client_for(server) as client:
        pre = await client.preflight(value)
    assert pre.mode == "profile"
    assert pre.switch_model is False
    assert pre.switch_effort is False
    assert not any(call[1] == "/api/acp/models" for call in server.calls)


async def test_preflight_override_validates_catalog_without_mutating_profile():
    value = task(secrets={"OPENCODE_API_KEY": {"kind": "LookupSecret", "url": "x"}})
    server = Server(value, profile_model=OTHER_MODEL)
    async with client_for(server) as client:
        pre = await client.preflight(value)
    assert pre.mode == "override"
    assert pre.switch_model is True
    assert pre.agent_settings["acp_model"] == DEFAULT_MODEL
    discovery = next(call for call in server.calls if call[1] == "/api/acp/models")
    assert discovery[2]["agent_settings"]["acp_model"] == DEFAULT_MODEL
    assert discovery[2]["secrets"] == dict(value.secrets)


async def test_preflight_effort_override_uses_native_effort_selection():
    value = task(expected_effort="high")
    server = Server(value)
    async with client_for(server) as client:
        pre = await client.preflight(value)
    assert pre.mode == "profile"
    assert pre.switch_model is False
    assert pre.switch_effort is True
    assert pre.effort == "high"


async def test_override_fails_closed_on_missing_catalog_model_or_effort():
    value = task(expected_effort="high")
    server = Server(value, profile_model=OTHER_MODEL)
    server.catalog = [{"model_id": OTHER_MODEL}]
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="not offered"):
            await client.start(value)
    assert not any(path == "/api/conversations" for _, path, _, _ in server.calls)

    server = Server(value)
    server.efforts = {}
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="effort"):
            await client.start(value)


async def test_dedicated_profile_mode_rejects_global_default_mismatch():
    value = task(allow_model_override=False)
    server = Server(value, profile_model=OTHER_MODEL)
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="model/effort"):
            await client.start(value)
    assert not any(call[1] == "/api/acp/models" for call in server.calls)


async def test_override_fails_closed_on_profile_mcp_refs():
    value = task()
    server = Server(value, profile_model=OTHER_MODEL)
    server.profile = {
        **server.profile,
        "acp_model": OTHER_MODEL,
        "mcp_server_refs": ["mcp"],
    }
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="MCP"):
            await client.start(value)


async def test_unknown_repository_is_not_approved_for_dispatch():
    value = task(repository="other/repo", issue_ref="other/repo#1")
    server = Server(value)
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="not approved"):
            await client.start(value)
    assert server.calls == []


async def test_start_creates_verifies_then_submits_task():
    value = task()
    server = Server(value)
    async with client_for(server) as client:
        result = await client.start(value)
    assert result.created is True
    assert result.repository == "yesvus/kule"
    assert result.conversation_id == CONVERSATION_ID
    assert result.branch == value.branch
    assert result.workspace == worktree(value)
    assert result.model == DEFAULT_MODEL
    assert result.effective_model == DEFAULT_MODEL
    assert result.model_verified is True
    assert result.state == "running"
    start_index = next(
        index
        for index, call in enumerate(server.calls)
        if call[0] == "POST" and call[1] == "/api/conversations"
    )
    events = [
        (index, call)
        for index, call in enumerate(server.calls)
        if call[1] == f"/api/conversations/{CONVERSATION_ID}/events"
    ]
    assert len(events) == 1
    event_index, event = events[0]
    assert start_index < event_index
    assert event[2] == build_task_message(value)
    assert server.calls[start_index][2]["worktree"] is True
    assert server.calls[start_index][2]["tags"]["kulerepo"] == "yesvus/kule"
    assert "initial_message" not in server.calls[start_index][2]


async def test_start_override_mode_selects_model_natively_and_filters_secrets():
    value = task(
        secrets={
            "OPENCODE_API_KEY": {"kind": "LookupSecret", "url": "x"},
            "UNRELATED": {"kind": "StaticSecret", "value": "y"},
        }
    )
    server = Server(value, profile_model=OTHER_MODEL)
    server.profile = {**server.profile, "secret_refs": ["OPENCODE_API_KEY"]}
    # Start from a different effective model so a no-op switch cannot pass.
    server.conversation = conversation(value, current_model_id=OTHER_MODEL)
    async with client_for(server) as client:
        result = await client.start(value)
    assert result.effective_model == DEFAULT_MODEL
    assert server.conversation["current_model_id"] == DEFAULT_MODEL
    start = next(call for call in server.calls if call[1] == "/api/conversations")
    assert "agent_profile_id" not in start[2]
    assert start[2]["agent_settings"]["acp_model"] == DEFAULT_MODEL
    assert set(start[2]["secrets"]) == {"OPENCODE_API_KEY"}
    switch = next(call for call in server.calls if call[1].endswith("/switch_acp_model"))
    assert switch[2] == {"model": DEFAULT_MODEL}


async def test_start_effort_is_selected_and_verified():
    value = task(expected_effort="high")
    server = Server(value)
    # Start without an effective effort so a no-op switch cannot pass.
    server.conversation = conversation(value, current_effort=None)
    async with client_for(server) as client:
        result = await client.start(value)
    assert result.effort == "high"
    assert result.effective_effort == "high"
    assert result.effort_verified is True
    assert server.conversation["current_effort"] == "high"
    switch = next(call for call in server.calls if call[1].endswith("/switch_acp_effort"))
    assert switch[2] == {"effort": "high"}


async def test_start_rejects_effective_model_mismatch_and_interrupts():
    value = task()
    server = Server(value)
    server.conversation = conversation(value, current_model_id=OTHER_MODEL)
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="effective model"):
            await client.start(value, model_verify_attempts=1)
    assert server.calls[-1][:2] == (
        "POST",
        f"/api/conversations/{CONVERSATION_ID}/interrupt",
    )


async def test_start_fails_closed_when_effective_model_is_not_reported():
    value = task()
    server = Server(value)
    server.conversation = conversation(value, current_model_id=None)
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="not reported"):
            await client.start(value, model_verify_attempts=1, model_verify_interval=0)
    assert server.calls[-1][:2] == (
        "POST",
        f"/api/conversations/{CONVERSATION_ID}/interrupt",
    )


async def test_duplicate_dispatch_reuses_only_the_same_identity():
    value = task()
    server = Server(value)
    server.start_status = 200
    async with client_for(server) as client:
        first = await client.start(value)
    assert first.created is False
    assert not any(call[1].endswith("/events") for call in server.calls)

    server = Server(value)
    server.start_status = 200
    server.echo_tags = False
    server.conversation = conversation(value, tags={**value.tags, "kulerepo": "other/repo"})
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="no approved repository scope"):
            await client.start(value)
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


async def test_duplicate_branch_or_effort_change_is_rejected_without_interrupt():
    value = task()
    changed = task(branch_prefix="different/", conversation_id=value.conversation_id)
    server = Server(changed)
    server.start_status = 200
    server.echo_tags = False
    server.conversation = conversation(value)
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="different task"):
            await client.start(changed)
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


@pytest.mark.parametrize(
    "override",
    [
        {"agent": {"kind": "ACPAgent", "acp_server": "opencode", "acp_model": "paid-model"}},
        {"workspace": {"kind": "LocalWorkspace", "working_dir": REPO_PATH}},
        {
            "workspace": {
                "kind": "LocalWorkspace",
                "working_dir": "/tmp/conversation-worktrees/not-this-conversation/kule",
            }
        },
    ],
)
async def test_unsafe_created_worker_is_interrupted(override):
    value = task()
    server = Server(value)
    server.conversation = conversation(value, **override)
    server.workspace_override = override.get("workspace")
    async with client_for(server) as client:
        with pytest.raises(WorkerError):
            await client.start(value, model_verify_attempts=1, model_verify_interval=0)
    assert server.calls[-1][:2] == (
        "POST",
        f"/api/conversations/{CONVERSATION_ID}/interrupt",
    )


async def test_201_invalid_body_preserves_status_and_interrupts():
    value = task()
    server = Server(value)

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST" and request.url.path == "/api/conversations":
            return httpx2.Response(201, content=b"not-json")
        return await server.handler(request)

    async with WorkerClient(
        "https://canvas.example",
        "synthetic-session-key",
        repositories=REPOSITORIES,
        transport=httpx2.MockTransport(handler),
    ) as client:
        with pytest.raises(WorkerError, match="invalid JSON"):
            await client.start(value)
    assert any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


async def test_200_invalid_body_never_interrupts_existing_worker():
    value = task()
    server = Server(value)

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST" and request.url.path == "/api/conversations":
            return httpx2.Response(200, content=b"not-json")
        return await server.handler(request)

    async with WorkerClient(
        "https://canvas.example",
        "synthetic-session-key",
        repositories=REPOSITORIES,
        transport=httpx2.MockTransport(handler),
    ) as client:
        with pytest.raises(WorkerError, match="invalid JSON"):
            await client.start(value)
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


class _NeverReadStream(httpx2.AsyncByteStream):
    def __init__(self) -> None:
        self.iterated = False

    async def __aiter__(self):
        self.iterated = True
        yield b"x"


async def test_oversized_response_is_rejected_before_streaming():
    value = task()
    server = Server(value)
    stream = _NeverReadStream()

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == f"/api/conversations/{CONVERSATION_ID}":
            return httpx2.Response(
                200,
                headers={"Content-Length": str(ww._MAX_RESPONSE_BYTES + 1)},
                stream=stream,
            )
        return await server.handler(request)

    async with WorkerClient(
        "https://canvas.example",
        "synthetic-session-key",
        repositories=REPOSITORIES,
        transport=httpx2.MockTransport(handler),
    ) as client:
        with pytest.raises(ww.WorkerResponseError, match="too large"):
            await client.status(value)
    assert stream.iterated is False


class _OversizedStream(httpx2.AsyncByteStream):
    def __init__(self) -> None:
        self.chunks = 0

    async def __aiter__(self):
        self.chunks += 1
        yield b"x" * (ww._MAX_RESPONSE_BYTES + 1)
        self.chunks += 1
        yield b"must not be read"


async def test_oversized_response_closes_stream_without_reading_past_the_cap():
    value = task()
    server = Server(value)
    stream = _OversizedStream()

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == f"/api/conversations/{CONVERSATION_ID}":
            return httpx2.Response(200, stream=stream)
        return await server.handler(request)

    async with WorkerClient(
        "https://canvas.example",
        "synthetic-session-key",
        repositories=REPOSITORIES,
        transport=httpx2.MockTransport(handler),
    ) as client:
        with pytest.raises(ww.WorkerResponseError, match="too large"):
            await client.status(value)
    assert stream.chunks == 1


async def test_run_retry_exhaustion_preserves_task_for_retry():
    value = task()
    server = Server(value)
    server.event_status = 429
    server.run_status = 429
    server.conversation = conversation(value, execution_status="idle")
    async with client_for(server) as client:
        with pytest.raises(WorkerRunPending) as err:
            await client.start(value)
    assert err.value.conversation_id == CONVERSATION_ID
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )
    first_events = [call for call in server.calls if call[1].endswith("/events")]
    assert len(first_events) == 1

    # Capacity returns; an identical retry only retries /run.
    server.run_status = 200
    server.start_status = 200
    server.task_accepted = True
    async with client_for(server) as client:
        result = await client.start(value)
    assert result.created is False
    assert result.model_verified is True
    assert len([call for call in server.calls if call[1].endswith("/events")]) == 1
    assert len([call for call in server.calls if call[1].endswith("/run")]) >= 4


async def test_409_run_is_active_success():
    value = task()
    server = Server(value)
    server.event_status = 429
    server.run_status = 409
    server.conversation = conversation(value, execution_status="running")
    async with client_for(server) as client:
        result = await client.start(value)
    assert result.model_verified is True
    assert any(call[1].endswith("/run") for call in server.calls)


async def test_409_run_polls_until_the_admitted_run_is_visible():
    value = task()
    server = Server(value)
    server.event_status = 429
    server.run_status = 409
    server.conversation = conversation(value, execution_status="idle")
    # Canvas can report idle for one read while ACP initializes the run
    # admitted by the previous (response-lost) request.
    server.get_status_script = ["idle", "running"]
    async with client_for(server) as client:
        result = await client.start(value)
    assert result.model_verified is True
    assert server.conversation["execution_status"] == "running"
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


async def test_409_run_that_never_starts_reports_pending_not_failure():
    value = task()
    server = Server(value)
    server.event_status = 429
    server.run_status = 409
    server.conversation = conversation(value, execution_status="idle")
    async with client_for(server) as client:
        with pytest.raises(WorkerRunPending):
            await client.start(value)
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )
    assert len([call for call in server.calls if call[1].endswith("/events")]) == 1


async def test_429_save_then_run_retry():
    value = task()
    server = Server(value)
    server.event_status = 429
    async with client_for(server) as client:
        result = await client.start(value)
    assert result.model_verified is True
    assert any(call[1] == f"/api/conversations/{CONVERSATION_ID}/run" for call in server.calls)


async def test_duplicate_idle_without_saved_task_replays_once():
    value = task()
    server = Server(value)
    server.start_status = 200
    server.task_accepted = False
    server.conversation = conversation(value, execution_status="idle")

    async def good(_: str) -> str:
        return value.branch

    async with client_for(server) as client:
        result = await client.start(value, branch_reader=good)
    assert result.created is False
    assert result.model_verified is True
    # Reconciliation must not discard the branch verification it just did.
    assert result.branch_verified is True
    events = [call for call in server.calls if call[1].endswith("/events")]
    assert len(events) == 1
    assert events[0][2] == build_task_message(value)


async def test_duplicate_idle_with_saved_task_only_retries_run():
    value = task()
    server = Server(value)
    server.start_status = 200
    server.task_accepted = True
    server.conversation = conversation(value, execution_status="idle")
    async with client_for(server) as client:
        result = await client.start(value)
    assert result.created is False
    assert result.model_verified is True
    assert not any(call[1].endswith("/events") for call in server.calls)
    assert any(call[1].endswith("/run") for call in server.calls)


def test_status_mapping_is_total_and_explicit():
    expected = {
        "idle": "pending",
        "running": "running",
        "paused": "paused",
        "waiting_for_confirmation": "needs_attention",
        "finished": "completed",
        "error": "failed",
        "stuck": "stuck",
        "deleting": "deleting",
        "some-future-state": "unknown",
    }
    for native, mapped in expected.items():
        assert map_status(native) == mapped
    assert map_status(None) == "unknown"


async def test_status_parses_evidence_only_when_terminal():
    value = task()
    server = Server(value)
    async with client_for(server) as client:
        running = await client.status(value)
    assert running.terminal is False
    assert running.pr is None
    assert not any("agent_final_response" in path for _, path, _, _ in server.calls)

    server = Server(value)
    server.conversation = conversation(value, execution_status="finished")
    async with client_for(server) as client:
        finished = await client.status(value)
    assert finished.terminal is True
    assert finished.state == "completed"
    assert finished.pr is not None
    assert finished.pr.pr_url == f"https://github.com/{value.repository}/pull/42"
    assert finished.evidence_error is None


async def test_status_reports_configured_only_or_mismatched_model():
    value = task()
    server = Server(value)
    server.conversation = conversation(value, current_model_id=None)
    async with client_for(server) as client:
        not_reported = await client.status(value)
    assert not_reported.model_verified is False
    assert "not reported" in (not_reported.model_error or "")

    server = Server(value)
    server.conversation = conversation(value, current_model_id=OTHER_MODEL)
    async with client_for(server) as client:
        mismatched = await client.status(value)
    assert mismatched.model_verified is False
    assert "does not match" in (mismatched.model_error or "")


async def test_status_final_response_failure_keeps_terminal_state():
    value = task()
    server = Server(value)
    server.conversation = conversation(value, execution_status="finished")
    server.final_status = 500
    async with client_for(server) as client:
        result = await client.status(value)
    assert result.state == "completed"
    assert result.terminal is True
    assert result.evidence_error is not None


async def test_status_accepts_blocker_only_evidence_without_pr():
    value = task()
    server = Server(value)
    server.conversation = conversation(value, execution_status="finished")
    server.final = (
        "Blocked.\n\n```worker-evidence\n"
        + json.dumps({"blockers": ["Git access denied"]})
        + "\n```\n"
    )
    async with client_for(server) as client:
        result = await client.status(value, verify_pr=True)
    assert result.pr is not None
    assert result.pr.pr_url is None
    assert result.pr.blockers == ("Git access denied",)
    assert result.pr_verification is None


async def test_status_enforces_repository_scope_and_legacy_mapping():
    value = task()
    server = Server(value)
    server.conversation = conversation(value, tags={**value.tags, "kulerepo": "other/repo"})
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="no approved repository scope"):
            await client.status(value)

    server = Server(value)
    server.conversation = conversation(value, tags={})
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="no approved repository scope"):
            await client.status(value)

    server = Server(value)
    server.conversation = conversation(
        value,
        tags={},
        workspace={"kind": "LocalWorkspace", "working_dir": REPO_PATH},
    )
    async with client_for(
        server, legacy_repository_by_id={CONVERSATION_ID: "yesvus/kule"}
    ) as client:
        result = await client.status(value)
    assert result.repository == "yesvus/kule"


async def test_legacy_conversation_cannot_be_reused_for_dispatch():
    value = task()
    server = Server(value)
    server.start_status = 200
    server.echo_tags = False
    server.conversation = conversation(value, tags={})
    async with client_for(
        server, legacy_repository_by_id={CONVERSATION_ID: "yesvus/kule"}
    ) as client:
        with pytest.raises(WorkerError, match="legacy conversation"):
            await client.start(value)
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


@pytest.mark.parametrize(
    ("block", "message"),
    [
        ("no evidence", "no worker-evidence"),
        (evidence_block(task(), branch="wrong-branch"), "different branch"),
        (
            evidence_block(task(), pr_url="https://github.com/other/repo/pull/1"),
            "different repository",
        ),
        (evidence_block(task(), commit="abc"), "40 lowercase"),
        (evidence_block(task(), tests=[]), "non-empty list"),
        (evidence_block(task(), pr_url="http://github.com/yesvus/kule/pull/42"), "pr_url"),
        (evidence_block(task(), pr_url="https://github.com/../kule/pull/42"), "pr_url"),
        (evidence_block(task(), pr_url="https://github.com/yesvus/../pull/42"), "pr_url"),
    ],
)
async def test_invalid_evidence_is_reported_not_raised(block, message):
    value = task()
    server = Server(value)
    server.conversation = conversation(value, execution_status="error")
    server.final = block
    async with client_for(server) as client:
        result = await client.status(value)
    assert result.state == "failed"
    assert result.pr is None
    assert message in (result.evidence_error or "")


async def test_branch_reader_verifies_actual_worktree_branch():
    value = task()
    server = Server(value)

    async def good(_: str) -> str:
        return value.branch

    async def bad(_: str) -> str:
        return "main"

    async with client_for(server) as client:
        result = await client.status(value, branch_reader=good)
        mismatch = await client.status(value, branch_reader=bad)
    assert result.branch_verified is True
    assert result.actual_branch == value.branch
    assert mismatch.branch_verified is False
    assert "does not match" in (mismatch.branch_error or "")


async def test_start_branch_reader_match_sets_verified():
    value = task()
    server = Server(value)

    async def good(_: str) -> str:
        return value.branch

    async with client_for(server) as client:
        result = await client.start(value, branch_reader=good)
    assert result.branch_verified is True


async def test_start_branch_reader_mismatch_interrupts_created_worker():
    value = task()
    server = Server(value)

    async def bad(_: str) -> str:
        return "main"

    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="does not match"):
            await client.start(value, branch_reader=bad)
    assert server.calls[-1][:2] == (
        "POST",
        f"/api/conversations/{CONVERSATION_ID}/interrupt",
    )


async def test_pr_verification_binds_exact_path_and_reports_branch_state():
    value = task()
    server = Server(value)
    server.conversation = conversation(value, execution_status="finished")
    async with client_for(server) as client:
        result = await client.status(value, verify_pr=True)
    assert result.pr_verification is not None
    assert result.pr_verification["verified"] is True
    assert result.pr_verification["branch_verified"] is True
    assert result.pr_verification["checks"] == "success"
    pr_call = next(call for call in server.calls if "/api/git/repositories/" in call[1])
    assert pr_call[1] == "/api/git/repositories/yesvus/kule/pull-requests/42"
    assert pr_call[3] == "provider=github"

    server = Server(value)
    server.conversation = conversation(value, execution_status="finished")
    server.pr = {**server.pr, "head_sha": "b" * 40}
    async with client_for(server) as client:
        result = await client.status(value, verify_pr=True)
    assert result.pr_verification is not None
    assert result.pr_verification["verified"] is False
    assert "head" in result.pr_verification["error"]

    server = Server(value)
    server.conversation = conversation(value, execution_status="finished")
    server.pr = {**server.pr, "head_ref": "other-branch"}
    async with client_for(server) as client:
        result = await client.status(value, verify_pr=True)
    assert result.pr_verification is not None
    assert result.pr_verification["verified"] is False
    assert "branch" in result.pr_verification["error"]

    server = Server(value)
    server.conversation = conversation(value, execution_status="finished")
    server.pr = {key: val for key, val in server.pr.items() if key != "head_ref"}
    async with client_for(server) as client:
        result = await client.status(value, verify_pr=True)
    assert result.pr_verification is not None
    assert result.pr_verification["branch_verified"] is None


async def test_stop_reports_actual_state_and_never_deletes():
    value = task()
    server = Server(value)
    async with client_for(server) as client:
        state = await client.stop(value)
    assert state.acknowledged is True
    assert state.state == "paused"
    assert server.calls[-1][:2] == (
        "GET",
        f"/api/conversations/{CONVERSATION_ID}",
    )
    assert "DELETE" not in server.methods()
    assert not hasattr(client, "delete")

    server = Server(value)
    server.conversation = conversation(value, execution_status="finished")
    async with client_for(server) as client:
        state = await client.stop(value)
    assert state.state == "completed"

    server = Server(value)
    server.conversation = conversation(value, tags={**value.tags, "kulerepo": "other/repo"})
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="no approved repository scope"):
            await client.stop(value)
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


async def test_list_repository_filters_pages_and_legacy_unknowns():
    value = task()
    other = task(
        issue_ref="yesvus/ops#9",
        repository="yesvus/ops",
        conversation_id=uuid4(),
        profile_id=PROFILE_ID,
    )
    legacy = task(conversation_id=uuid4())
    untagged = task(conversation_id=uuid4())
    extra = task(conversation_id=uuid4())
    server = Server(value, repositories={**REPOSITORIES, "yesvus/ops": "/workspace/src/ops"})
    server.search_pages = [
        {
            "items": [
                conversation(value),
                conversation(other),
                conversation(untagged, tags={}),
            ],
            "next_page_id": "1",
        },
        {
            "items": [
                conversation(legacy, tags={}),
                conversation(extra),
            ],
            "next_page_id": None,
        },
    ]
    async with client_for(
        server, legacy_repository_by_id={legacy.conversation_id: "yesvus/kule"}
    ) as client:
        result = await client.list_repository("yesvus/kule")
    assert result.repository == "yesvus/kule"
    assert result.pages == 2
    assert result.unclassified_count == 1
    assert {item.conversation_id for item in result.items} == {
        value.conversation_id,
        legacy.conversation_id,
        extra.conversation_id,
    }
    assert next(
        item for item in result.items if item.conversation_id == legacy.conversation_id
    ).legacy
    assert all(item.repository == "yesvus/kule" for item in result.items)


async def test_list_repository_is_bounded_and_never_infers_scope():
    value = task()
    server = Server(value)
    many = [conversation(task(conversation_id=uuid4())) for _ in range(3)]
    server.search_pages = [{"items": many, "next_page_id": None}]
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="result bound"):
            await client.list_repository("yesvus/kule", max_results=2)

    server = Server(value)
    server.search_pages = [
        {"items": [conversation(value)], "next_page_id": "1"},
        {"items": [conversation(value)], "next_page_id": None},
    ]
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="page bound"):
            await client.list_repository("yesvus/kule", max_pages=1)

    server = Server(value)
    server.search_pages = [{"items": [conversation(value, tags={})], "next_page_id": None}]
    async with client_for(server) as client:
        result = await client.list_repository("yesvus/kule")
    assert result.items == ()
    assert result.unclassified_count == 1


async def test_same_id_start_is_serialized_and_different_ids_run_in_parallel():
    value = task()
    server = Server(value)
    server.auto_start = True
    server.start_delay = 0.05
    async with client_for(server, max_concurrent_starts=2) as client:
        first, second = await asyncio.gather(
            client.start(value, model_verify_attempts=1, model_verify_interval=0),
            client.start(value, model_verify_attempts=1, model_verify_interval=0),
        )
    assert server.max_active_starts == 1
    assert {first.created, second.created} == {True, False}
    assert len([call for call in server.calls if call[1].endswith("/events")]) == 1

    tasks = [task(conversation_id=uuid4()) for _ in range(3)]
    server = Server(tasks[0])
    server.start_delay = 0.05
    async with client_for(server, max_concurrent_starts=2) as client:
        results = await asyncio.gather(
            *(
                client.start(item, model_verify_attempts=1, model_verify_interval=0)
                for item in tasks
            )
        )
    assert {item.conversation_id for item in results} == {item.conversation_id for item in tasks}
    assert server.max_active_starts == 2


async def test_start_timeout_does_not_interrupt_ambiguous_worker(monkeypatch):
    value = task()
    server = Server(value)
    client = client_for(server)
    original = client._request

    async def slow(method, path, **kwargs):
        if method == "POST" and path == "/api/conversations":
            raise ww._HTTPTimeout("synthetic timeout")
        return await original(method, path, **kwargs)

    monkeypatch.setattr(client, "_request", slow)
    with pytest.raises(WorkerTimeout) as err:
        await client.start(value, model_verify_attempts=1, model_verify_interval=0)
    assert err.value.conversation_id == CONVERSATION_ID
    # A lost create response cannot prove this request created the worker, so
    # reconciliation must not interrupt a possibly reused conversation.
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )
    await client.aclose()


async def test_cancel_after_create_admission_interrupts_created_worker():
    value = task()
    server = Server(value)
    admitted = asyncio.Event()
    release = asyncio.Event()

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST" and request.url.path == "/api/conversations":
            admitted.set()
            await release.wait()
        return await server.handler(request)

    async with WorkerClient(
        "https://canvas.example",
        "synthetic-session-key",
        repositories=REPOSITORIES,
        transport=httpx2.MockTransport(handler),
    ) as client:
        running = asyncio.create_task(client.start(value))
        await admitted.wait()
        running.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await running
    assert any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


async def test_cancel_during_reused_create_does_not_interrupt_existing_worker():
    value = task()
    server = Server(value)
    server.start_status = 200
    admitted = asyncio.Event()
    release = asyncio.Event()

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST" and request.url.path == "/api/conversations":
            admitted.set()
            await release.wait()
        return await server.handler(request)

    async with WorkerClient(
        "https://canvas.example",
        "synthetic-session-key",
        repositories=REPOSITORIES,
        transport=httpx2.MockTransport(handler),
    ) as client:
        running = asyncio.create_task(client.start(value))
        await admitted.wait()
        running.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await running
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


async def test_cancel_during_pending_run_retry_does_not_interrupt_saved_task():
    value = task()
    server = Server(value)
    server.start_status = 200
    server.task_accepted = True
    server.conversation = conversation(value, execution_status="idle")
    server.run_status = 429
    run_started = asyncio.Event()
    release = asyncio.Event()

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST" and request.url.path.endswith("/run"):
            run_started.set()
            await release.wait()
        return await server.handler(request)

    async with WorkerClient(
        "https://canvas.example",
        "synthetic-session-key",
        repositories=REPOSITORIES,
        transport=httpx2.MockTransport(handler),
    ) as client:
        running = asyncio.create_task(client.start(value))
        await run_started.wait()
        running.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await running
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


async def test_cancel_after_confirmed_run_admission_interrupts_reused_worker():
    value = task()
    server = Server(value)
    server.start_status = 200
    server.task_accepted = True
    server.conversation = conversation(value, execution_status="idle")
    run_done = asyncio.Event()
    verify_blocked = asyncio.Event()
    release = asyncio.Event()

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST" and request.url.path.endswith("/run"):
            response = await server.handler(request)
            run_done.set()
            return response
        if (
            request.method == "GET"
            and request.url.path == f"/api/conversations/{CONVERSATION_ID}"
            and run_done.is_set()
        ):
            verify_blocked.set()
            await release.wait()
        return await server.handler(request)

    async with WorkerClient(
        "https://canvas.example",
        "synthetic-session-key",
        repositories=REPOSITORIES,
        transport=httpx2.MockTransport(handler),
    ) as client:
        running = asyncio.create_task(client.start(value))
        await verify_blocked.wait()
        running.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await running
    assert any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


async def test_replayed_task_failing_verification_interrupts_admitted_run():
    value = task()
    server = Server(value)
    server.start_status = 200
    server.task_accepted = False
    server.conversation = conversation(value, execution_status="idle", current_model_id=OTHER_MODEL)
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="effective model"):
            await client.start(value, model_verify_attempts=1, model_verify_interval=0)
    assert server.calls[-1][:2] == (
        "POST",
        f"/api/conversations/{CONVERSATION_ID}/interrupt",
    )


async def test_cancel_before_create_admission_sends_no_request():
    value = task()
    server = Server(value)
    blocked = asyncio.Event()
    release = asyncio.Event()

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/api/agent-profiles":
            blocked.set()
            await release.wait()
        return await server.handler(request)

    async with WorkerClient(
        "https://canvas.example",
        "synthetic-session-key",
        repositories=REPOSITORIES,
        transport=httpx2.MockTransport(handler),
    ) as client:
        running = asyncio.create_task(client.start(value))
        await blocked.wait()
        running.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await running
    assert not any(path == "/api/conversations" for _, path, _, _ in server.calls)
    assert not any(
        path == f"/api/conversations/{CONVERSATION_ID}/interrupt" for _, path, _, _ in server.calls
    )


def test_api_origin_key_proxy_and_repository_mapping_are_exact():
    with pytest.raises(WorkerError):
        WorkerClient("http://canvas.example", "key", repositories=REPOSITORIES)
    with pytest.raises(WorkerError):
        WorkerClient("https://canvas.example/api", "key", repositories=REPOSITORIES)
    with pytest.raises(WorkerError):
        WorkerClient("https://canvas.example?x=1", "key", repositories=REPOSITORIES)
    with pytest.raises(WorkerError):
        WorkerClient("https://canvas.example", "", repositories=REPOSITORIES)
    with pytest.raises(WorkerError):
        WorkerClient("https://canvas.example", "key", repositories={})
    with pytest.raises(WorkerError):
        WorkerClient(
            "https://canvas.example",
            "key",
            repositories=REPOSITORIES,
            legacy_repository_by_id={CONVERSATION_ID: "not-approved/repo"},
        )
    client = WorkerClient("https://canvas.example", "key", repositories=REPOSITORIES)
    assert getattr(client._client, "_trust_env", None) is False
    assert ww.PINNED_SDK_TAG == "v1.62.0"
    assert ww.REPOSITORY_TAG == "kulerepo"


def test_evidence_text_is_redacted_and_bounded():
    value = task()
    parsed = parse_pr_evidence(
        evidence_block(value, tests=["pytest: api_key=supersecretvalue passed"]),
        value,
    )
    assert parsed.tests
    assert "supersecretvalue" not in parsed.tests[0]
    assert "[REDACTED]" in parsed.tests[0]


def test_evidence_parser_uses_last_block_and_accepts_blocker_only():
    value = task()
    first = evidence_block(value, pr_url="https://github.com/yesvus/kule/pull/1")
    last = evidence_block(value, pr_url="https://github.com/yesvus/kule/pull/2")
    parsed = parse_pr_evidence(first + last, value)
    assert parsed.pr_url is not None
    assert parsed.pr_url.endswith("/2")

    blocker = parse_pr_evidence('```worker-evidence\n{"blockers": ["no git access"]}\n```\n', value)
    assert blocker.pr_url is None
    assert blocker.blockers == ("no git access",)


def test_agent_settings_allows_blank_command_and_empty_args():
    settings = ww._agent_settings_from_profile(
        {
            "acp_server": "opencode",
            "acp_model": DEFAULT_MODEL,
            "acp_command": " ",
            "acp_args": [""],
        },
        DEFAULT_MODEL,
        None,
    )
    assert "acp_command" not in settings
    assert settings["acp_args"] == [""]
    # Empty argument tokens after a valid executable are preserved.
    assert ww._agent_settings_from_profile(
        {
            "acp_server": "opencode",
            "acp_model": DEFAULT_MODEL,
            "acp_command": ["opencode", ""],
        },
        DEFAULT_MODEL,
        None,
    )["acp_command"] == ["opencode", ""]
    for bad in (["", "arg"], [""], '""'):
        with pytest.raises(WorkerError, match="command is invalid"):
            ww._agent_settings_from_profile(
                {
                    "acp_server": "opencode",
                    "acp_model": DEFAULT_MODEL,
                    "acp_command": bad,
                },
                DEFAULT_MODEL,
                None,
            )

    with pytest.raises(WorkerError, match="custom ACP"):
        ww._agent_settings_from_profile(
            {"acp_server": "custom", "acp_model": DEFAULT_MODEL, "acp_command": ""},
            DEFAULT_MODEL,
            None,
        )


def test_prompt_carries_issue_scope_pr_and_blocker_contract():
    text = build_prompt(task())
    assert ISSUE in text
    assert "only inside your assigned worktree" in text
    assert "Never push the default branch" in text
    assert "worker-evidence" in text
    assert "blocker-only" in text
