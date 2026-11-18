"""Source-only worker contract tests. No OpenHands server, cluster or secrets."""

from __future__ import annotations

import asyncio
import json
from uuid import UUID, uuid4

import httpx2
import pytest

from operator_mcp import worker_workflow as ww
from operator_mcp.worker_workflow import (
    DEFAULT_MODEL,
    WorkerClient,
    WorkerError,
    WorkerTask,
    WorkerTimeout,
    build_prompt,
    build_start_request,
    map_status,
    parse_pr_evidence,
    validate_model,
)

PROFILE_ID = UUID("11111111-1111-4111-8111-111111111111")
CONVERSATION_ID = UUID("22222222-2222-4222-8222-222222222222")
COMMIT = "a" * 40
WORKTREE = f"/tmp/conversation-worktrees/{CONVERSATION_ID}/kule"
REPO_PATH = "/workspace/src/kule"
ISSUE = "yesvus/kule#23"


def task(**overrides) -> WorkerTask:
    values = {
        "issue_ref": ISSUE,
        "repository": "yesvus/kule",
        "repo_path": REPO_PATH,
        "task": "Implement the source-only worker workflow.",
        "profile_id": PROFILE_ID,
        "expected_model": DEFAULT_MODEL,
        "branch_prefix": "oh23/ws-oh-workers/",
        "conversation_id": CONVERSATION_ID,
        "max_budget_per_run": 2.0,
    }
    values.update(overrides)
    return WorkerTask(**values)


def profile(task_value: WorkerTask, **overrides) -> dict:
    payload = {
        "id": str(task_value.profile_id),
        "name": "opencode-economical",
        "agent_kind": "acp",
        "acp_server": task_value.expected_acp_server,
        "acp_model": task_value.expected_model,
    }
    payload.update(overrides)
    return payload


def conversation(task_value: WorkerTask, **overrides) -> dict:
    payload = {
        "id": str(task_value.conversation_id),
        "execution_status": "running",
        "tags": dict(task_value.tags),
        "workspace": {
            "kind": "LocalWorkspace",
            "working_dir": f"/tmp/conversation-worktrees/{task_value.conversation_id}/kule",
        },
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

    def __init__(self, task_value: WorkerTask) -> None:
        self.task = task_value
        self.calls: list[tuple[str, str, dict | None, str]] = []
        self.start_status = 201
        self.profile = profile(task_value)
        self.conversation = conversation(task_value)
        self.final = evidence_block(task_value)
        self.pr = {
            "url": f"https://github.com/{task_value.repository}/pull/42",
            "head_sha": COMMIT,
            "state": "open",
            "checks": "success",
            "draft": False,
        }
        self.start_delay = 0.0
        self.active_starts = 0
        self.max_active_starts = 0
        self.workspace_override: dict | None = None

    async def handler(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, request.url.path, body, request.url.query.decode()))
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
        if request.method == "GET" and path == "/api/agent-profiles/opencode-economical":
            return httpx2.Response(
                200, json={"name": "opencode-economical", "profile": self.profile}
            )
        if request.method == "POST" and path == "/api/conversations":
            self.active_starts += 1
            self.max_active_starts = max(self.max_active_starts, self.active_starts)
            if self.start_delay:
                await asyncio.sleep(self.start_delay)
            self.active_starts -= 1
            conversation_id = body["conversation_id"]
            info = {
                **self.conversation,
                "id": conversation_id,
                "workspace": self.workspace_override
                or {
                    "kind": "LocalWorkspace",
                    "working_dir": f"/tmp/conversation-worktrees/{conversation_id}/kule",
                },
            }
            return httpx2.Response(self.start_status, json=info)
        if request.method == "GET" and path == f"/api/conversations/{self.task.conversation_id}":
            return httpx2.Response(200, json=self.conversation)
        if (
            request.method == "GET"
            and path == f"/api/conversations/{self.task.conversation_id}/agent_final_response"
        ):
            return httpx2.Response(200, json={"response": self.final})
        if (
            request.method == "POST"
            and path == f"/api/conversations/{self.task.conversation_id}/interrupt"
        ):
            return httpx2.Response(200, json={"success": True})
        if request.method == "GET" and "/api/git/repositories/" in path:
            return httpx2.Response(200, json=self.pr)
        return httpx2.Response(404, json={"detail": "not found"})

    def methods(self) -> list[str]:
        return [method for method, _, _, _ in self.calls]


def client_for(server: Server, **kwargs) -> WorkerClient:
    return WorkerClient(
        "https://canvas.example",
        "synthetic-session-key",
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
    # A well-formed but non-matching ID is rejected by exact profile equality
    # at preflight, not by guessing which suffixes look like display names.
    wrong = task(expected_model="opencode-go/deepseek-v4.1-flash-1017")
    assert wrong.expected_model != DEFAULT_MODEL


def test_task_has_unique_branch_and_native_idempotency_tags():
    first = task()
    second = task(conversation_id=uuid4(), task="Different work.")
    assert first.branch == "oh23/ws-oh-workers/22222222-2222-4222-8222-222222222222"
    assert first.branch != second.branch
    assert first.tags["kuletask"] != second.tags["kuletask"]
    assert first.tags["kuleissue"] == ISSUE
    assert first.tags["kuletask"] == first.task_digest
    assert first.tags["kulemodel"] == DEFAULT_MODEL
    assert len(first.tags["kulerepopath"]) == 16
    with pytest.raises(WorkerError):
        task(branch_prefix="../escape/")
    with pytest.raises(WorkerError):
        task(branch_prefix="oh23//worker/")
    with pytest.raises(WorkerError):
        task(repo_path="relative/repo")


def test_start_request_matches_pinned_upstream_schema():
    value = task()
    body = build_start_request(value)
    assert body["workspace"] == {"kind": "LocalWorkspace", "working_dir": REPO_PATH}
    assert body["worktree"] is True
    assert body["worktree_options"] == {
        "base": "default_branch",
        "branch_prefix": "oh23/ws-oh-workers/",
    }
    assert body["conversation_id"] == str(CONVERSATION_ID)
    assert body["agent_profile_id"] == str(PROFILE_ID)
    assert body["conversation_runtime"] == "local"
    assert body["max_iterations"] == 80
    assert body["max_budget_per_run"] == 2.0
    assert body["autotitle"] is False
    assert "agent" not in body and "agent_settings" not in body
    assert body["tags"] == value.tags
    message = body["initial_message"]
    assert message["role"] == "user"
    assert message["content"][0]["type"] == "text"
    assert "worker-evidence" in message["content"][0]["text"]
    assert "Do not deploy" in message["content"][0]["text"]
    assert value.branch in message["content"][0]["text"]


def test_prompt_carries_issue_scope_and_pr_contract():
    text = build_prompt(task())
    assert ISSUE in text
    assert "only inside your assigned worktree" in text
    assert "Never push the default branch" in text
    assert "worker-evidence" in text


async def test_preflight_rejects_wrong_profile_before_dispatch():
    value = task()
    server = Server(value)
    server.profile = profile(value, acp_model="opencode-go/deepseek-v4-pro")
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="model"):
            await client.start(value)
    assert "POST" not in server.methods()


async def test_preflight_rejects_display_name_model_before_dispatch():
    value = task(expected_model="opencode-go/deepseek-v4.1-flash-1017")
    server = Server(value)
    server.profile = profile(value, acp_model=DEFAULT_MODEL)
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="model"):
            await client.start(value)
    assert "POST" not in server.methods()


async def test_preflight_rejects_non_acp_profile():
    value = task()
    server = Server(value)
    server.profile = profile(value, agent_kind="openhands")
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="not ACP"):
            await client.start(value)
    assert "POST" not in server.methods()


async def test_start_returns_real_id_and_verifies_native_worktree():
    value = task()
    server = Server(value)
    async with client_for(server) as client:
        result = await client.start(value)
    assert result.created is True
    assert result.conversation_id == CONVERSATION_ID
    assert result.branch == value.branch
    assert result.workspace == WORKTREE
    assert result.model == DEFAULT_MODEL
    assert result.acp_server == "opencode"
    assert result.state == "running"
    start = next(call for call in server.calls if call[0] == "POST")
    assert start[2]["worktree"] is True
    assert start[2]["tags"] == value.tags


async def test_duplicate_dispatch_reuses_only_the_same_task():
    value = task()
    server = Server(value)
    server.start_status = 200
    async with client_for(server) as client:
        first = await client.start(value)
    assert first.created is False

    server = Server(value)
    server.start_status = 200
    server.conversation = conversation(value, tags={"kuleissue": "other/repo#1"})
    async with client_for(server) as client:
        with pytest.raises(WorkerError, match="different task"):
            await client.start(value)
    # A 200 is someone else's existing conversation: report the collision but
    # never interrupt it.
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
async def test_unsafe_start_is_interrupted(override):
    value = task()
    server = Server(value)
    server.conversation = conversation(value, **override)
    server.workspace_override = override.get("workspace")
    async with client_for(server) as client:
        with pytest.raises(WorkerError):
            await client.start(value)
    assert server.calls[-1][:2] == (
        "POST",
        f"/api/conversations/{CONVERSATION_ID}/interrupt",
    )


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
    assert finished.pr.branch == value.branch
    assert finished.pr.commit == COMMIT
    assert finished.evidence_error is None


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


async def test_pr_verification_binds_url_head_and_ci():
    value = task()
    server = Server(value)
    server.conversation = conversation(value, execution_status="finished")
    async with client_for(server) as client:
        result = await client.status(value, verify_pr=True)
    assert result.pr_verification == {
        "verified": True,
        "state": "open",
        "checks": "success",
        "draft": False,
        "head_sha": COMMIT,
    }
    assert not any(method == "DELETE" for method in server.methods())
    pr_call = next(call for call in server.calls if "/api/git/repositories/" in call[1])
    assert pr_call[3] == "provider=github"

    server = Server(value)
    server.conversation = conversation(value, execution_status="finished")
    server.pr = {**server.pr, "head_sha": "b" * 40}
    async with client_for(server) as client:
        result = await client.status(value, verify_pr=True)
    assert result.pr_verification is not None
    assert result.pr_verification["verified"] is False
    assert "head" in result.pr_verification["error"]


async def test_stop_interrupts_and_never_deletes_native_worktree():
    value = task()
    server = Server(value)
    async with client_for(server) as client:
        state = await client.stop(value.conversation_id)
    assert state == "paused"
    assert server.calls[-1][:2] == (
        "POST",
        f"/api/conversations/{CONVERSATION_ID}/interrupt",
    )
    assert "DELETE" not in server.methods()
    assert not hasattr(client, "delete")


async def test_bounded_concurrency_does_not_queue_a_new_runtime():
    tasks = [task(conversation_id=uuid4()) for _ in range(3)]
    server = Server(tasks[0])
    server.start_delay = 0.05
    async with client_for(server, max_concurrent=2) as client:
        results = await asyncio.gather(*(client.start(item) for item in tasks))
    assert {item.conversation_id for item in results} == {item.conversation_id for item in tasks}
    assert server.max_active_starts == 2


async def test_start_timeout_keeps_client_generated_id(monkeypatch):
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
        await client.start(value)
    assert err.value.conversation_id == CONVERSATION_ID
    await client.aclose()


def test_api_origin_and_key_are_exact():
    with pytest.raises(WorkerError):
        WorkerClient("http://canvas.example", "key")
    with pytest.raises(WorkerError):
        WorkerClient("https://canvas.example/api", "key")
    with pytest.raises(WorkerError):
        WorkerClient("https://canvas.example?x=1", "key")
    with pytest.raises(WorkerError):
        WorkerClient("https://canvas.example", "")
    assert ww.PINNED_SDK_TAG == "v1.62.0"


def test_evidence_text_is_redacted_and_bounded():
    value = task()
    parsed = parse_pr_evidence(
        evidence_block(value, tests=["pytest: api_key=supersecretvalue passed"]),
        value,
    )
    assert "supersecretvalue" not in parsed.tests[0]
    assert "[REDACTED]" in parsed.tests[0]


def test_evidence_parser_selects_the_last_valid_block():
    value = task()
    first = evidence_block(value, pr_url="https://github.com/yesvus/kule/pull/1")
    last = evidence_block(value, pr_url="https://github.com/yesvus/kule/pull/2")
    parsed = parse_pr_evidence(first + last, value)
    assert parsed.pr_url.endswith("/2")
