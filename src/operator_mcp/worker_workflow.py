"""Source-only OpenHands worker dispatch for one issue/branch/worktree/conversation.

The upstream agent server owns worktree creation, conversation lifecycle and
cleanup. This module only builds and checks the native request, reports status
and validates the worker's PR evidence. It does not start another runtime, keep
a queue or persist a second conversation store.

Schema reference: OpenHands software-agent-sdk v1.62.0
(commit 504a88cab0fb48ee5226238ad7b8f1d865fa84a8). The fields used here are in
``openhands-sdk/openhands/sdk/conversation/request.py`` and the HTTP routes in
``openhands-agent-server/openhands/agent_server/conversation_router.py``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4

import httpx2

from .redact import redact_text

# The issue asked for ``opencode-go/deepseek-v4.1-flash-1017``. The selectable
# OpenCode model ID is ``opencode-go/deepseek-v4.1-flash``; "DeepSeek V4.1
# Flash 1017" is its display name. Do not accept the display-name variant as a
# model ID or silently fall back to a different (possibly paid) model.
DEFAULT_MODEL = "opencode-go/deepseek-v4.1-flash"
DEFAULT_ACP_SERVER = "opencode"

PINNED_SDK_TAG = "v1.62.0"
PINNED_SDK_COMMIT = "504a88cab0fb48ee5226238ad7b8f1d865fa84a8"

API_KEY_ENV = "KULE_OPENHANDS_API_KEY"
API_URL_ENV = "KULE_OPENHANDS_API_URL"

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_TASK_BYTES = 20_000
_MAX_TEXT = 300
_MAX_BLOCKER = 500

_ISSUE_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[1-9][0-9]*$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
# Mirrors the upstream GIT_BRANCH_PREFIX_PATTERN, with a stricter no-dotdot rule.
_BRANCH_PREFIX_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._/-]*)?$")
_PR_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_EVIDENCE_RE = re.compile(
    r"```worker-evidence[ \t]*\r?\n(\{.*?\})\r?\n```",
    re.DOTALL,
)

# Upstream ConversationExecutionStatus values.
_STATUS_MAP = {
    "idle": "pending",
    "running": "running",
    "paused": "paused",
    "waiting_for_confirmation": "needs_attention",
    "finished": "completed",
    "error": "failed",
    "stuck": "stuck",
    "deleting": "deleting",
}
_TERMINAL = frozenset({"finished", "error", "stuck"})


class WorkerError(RuntimeError):
    """A safe, bounded worker-dispatch error."""


class WorkerTimeout(WorkerError):
    """The start request timed out after possibly creating the conversation.

    The caller can use ``conversation_id`` to query native status before
    retrying; this module never assumes the creation failed.
    """

    def __init__(self, message: str, conversation_id: UUID) -> None:
        super().__init__(message)
        self.conversation_id = conversation_id


class _HTTPTimeout(WorkerError):
    """Internal transport timeout with no conversation assumptions."""


@dataclass(frozen=True)
class WorkerTask:
    """One independent issue worker, with a unique native conversation.

    ``conversation_id`` is generated once per dispatch. Pass the same value to
    a retry to make OpenHands reuse that native conversation (HTTP 200) instead
    of creating another worktree. A different task or model must not reuse it.
    """

    issue_ref: str
    repository: str
    repo_path: str
    task: str
    profile_id: UUID
    expected_model: str = DEFAULT_MODEL
    expected_acp_server: str = DEFAULT_ACP_SERVER
    branch_prefix: str = "openhands/"
    conversation_id: UUID = field(default_factory=uuid4)
    max_iterations: int = 80
    max_budget_per_run: float = 2.0
    timeout_seconds: float = 60.0
    autotitle: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.issue_ref, str)
            or len(self.issue_ref) > 200
            or not _ISSUE_RE.fullmatch(self.issue_ref)
        ):
            raise WorkerError("issue_ref must look like owner/repository#number")
        if (
            not isinstance(self.repository, str)
            or len(self.repository) > 150
            or not _REPO_RE.fullmatch(self.repository)
        ):
            raise WorkerError("repository must look like owner/name")
        if not isinstance(self.repo_path, str) or not Path(self.repo_path).is_absolute():
            raise WorkerError("repo_path must be an absolute server-side path")
        if "\x00" in self.repo_path or len(self.repo_path) > 1024:
            raise WorkerError("repo_path is invalid")
        if not isinstance(self.task, str) or not self.task.strip():
            raise WorkerError("task must not be empty")
        if len(self.task.encode("utf-8")) > _MAX_TASK_BYTES:
            raise WorkerError(f"task must be at most {_MAX_TASK_BYTES} UTF-8 bytes")
        if not isinstance(self.profile_id, UUID):
            raise WorkerError("profile_id must be a UUID")
        validate_model(self.expected_model)
        if self.expected_acp_server not in {"opencode", "codex", "claude-code", "custom"}:
            raise WorkerError("expected_acp_server is not a supported ACP profile")
        _validate_branch_prefix(self.branch_prefix)
        if not isinstance(self.max_iterations, int) or isinstance(self.max_iterations, bool):
            raise WorkerError("max_iterations must be an integer")
        if not 1 <= self.max_iterations <= 1000:
            raise WorkerError("max_iterations must be between 1 and 1000")
        if (
            not isinstance(self.max_budget_per_run, int | float)
            or isinstance(self.max_budget_per_run, bool)
            or not math.isfinite(self.max_budget_per_run)
            or not 0 < self.max_budget_per_run <= 50
        ):
            raise WorkerError("max_budget_per_run must be between 0 and 50 USD")
        if (
            not isinstance(self.timeout_seconds, int | float)
            or isinstance(self.timeout_seconds, bool)
            or not 1 <= self.timeout_seconds <= 300
        ):
            raise WorkerError("timeout_seconds must be between 1 and 300")

    @property
    def branch(self) -> str:
        """The branch the upstream worktree planner creates: prefix + id."""
        return f"{self.branch_prefix}{self.conversation_id}"

    @property
    def task_digest(self) -> str:
        return hashlib.sha256(self.task.encode("utf-8")).hexdigest()[:16]

    @property
    def tags(self) -> dict[str, str]:
        """Native conversation tags used to detect an unsafe id reuse."""
        path_digest = hashlib.sha256(self.repo_path.encode("utf-8")).hexdigest()[:16]
        return {
            "kuleissue": self.issue_ref,
            "kuletask": self.task_digest,
            "kulemodel": self.expected_model,
            "kulerepopath": path_digest,
        }


@dataclass(frozen=True)
class PullRequestEvidence:
    pr_url: str
    branch: str
    commit: str
    tests: tuple[str, ...]
    blockers: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "pr_url": self.pr_url,
            "branch": self.branch,
            "commit": self.commit,
            "tests": list(self.tests),
            "blockers": list(self.blockers),
        }


@dataclass(frozen=True)
class WorkerDispatch:
    conversation_id: UUID
    branch: str
    workspace: str
    model: str
    acp_server: str
    created: bool
    raw_status: str
    state: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": str(self.conversation_id),
            "branch": self.branch,
            "workspace": self.workspace,
            "model": self.model,
            "acp_server": self.acp_server,
            "created": self.created,
            "status": self.raw_status,
            "state": self.state,
        }


@dataclass(frozen=True)
class WorkerStatus:
    conversation_id: UUID
    branch: str
    workspace: str
    model: str
    acp_server: str
    raw_status: str
    state: str
    terminal: bool
    pr: PullRequestEvidence | None = None
    pr_verification: dict[str, Any] | None = None
    evidence_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": str(self.conversation_id),
            "branch": self.branch,
            "workspace": self.workspace,
            "model": self.model,
            "acp_server": self.acp_server,
            "status": self.raw_status,
            "state": self.state,
            "terminal": self.terminal,
            "pr": self.pr.as_dict() if self.pr else None,
            "pr_verification": self.pr_verification,
            "evidence_error": self.evidence_error,
        }


def validate_model(model: str) -> str:
    """Require one exact selectable model ID; never a prefix, glob or alias."""
    if not isinstance(model, str) or not model or model != model.strip():
        raise WorkerError("expected_model must be one exact non-empty model ID")
    if len(model) > 200 or not _MODEL_RE.fullmatch(model) or ".." in model:
        raise WorkerError("expected_model is not a valid model ID")
    return model


def map_status(raw: str) -> str:
    """Map a native execution status to the worker's small state vocabulary."""
    if not isinstance(raw, str):
        return "unknown"
    return _STATUS_MAP.get(raw, "unknown")


def _validate_branch_prefix(prefix: str) -> None:
    if not isinstance(prefix, str) or len(prefix) > 200:
        raise WorkerError("branch_prefix is invalid")
    if not _BRANCH_PREFIX_RE.fullmatch(prefix) or ".." in prefix or "//" in prefix:
        raise WorkerError("branch_prefix is not a safe git branch prefix")


def _safe_line(value: Any, *, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise WorkerError(f"{name} must be a non-empty single line under {limit} chars")
    if "\n" in value or "\r" in value or "\x00" in value:
        raise WorkerError(f"{name} must be a single line")
    return value.strip()


def _safe_url(base: str) -> str:
    if not isinstance(base, str) or not base or base != base.strip():
        raise WorkerError("OpenHands API URL must be one exact HTTPS origin")
    if "?" in base or "#" in base:
        raise WorkerError("OpenHands API URL must not carry a query or fragment")
    try:
        parsed = urlsplit(base.rstrip("/"))
    except ValueError:
        raise WorkerError("OpenHands API URL is invalid") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise WorkerError("OpenHands API URL must be an HTTPS origin without a path")
    return base.rstrip("/")


def api_key_from_env(env: Mapping[str, str] | None = None) -> str:
    source = os.environ if env is None else env
    value = source.get(API_KEY_ENV, "")
    if not value or value != value.strip():
        raise WorkerError(f"{API_KEY_ENV} is not set")
    return value


def build_prompt(task: WorkerTask) -> str:
    """Self-contained brief; the server appends the native worktree guidance."""
    return (
        f"You are an independent worker for {task.issue_ref} in {task.repository}.\n\n"
        f"Use only the dedicated git worktree described by the server. It is on branch "
        f"`{task.branch}`. Do not switch back to the original repository checkout and do "
        "not create or switch branches.\n\n"
        f"Scope:\n{task.task}\n\n"
        "Rules:\n"
        "- Work only inside your assigned worktree. Do not edit another agent's worktree, "
        "unrelated conversations or shared registry/auth files.\n"
        "- Commit on the branch above and push only that branch. Never push the default "
        "branch, force-push, rewrite history or merge.\n"
        "- Open one pull request against the repository default branch, referencing "
        f"{task.issue_ref}. Do not deploy, change production or access secrets.\n"
        "- Run focused tests. Report the exact commands and complete results.\n"
        "- If Git access or scope is blocked, stop and report the blocker.\n\n"
        "End your final message with exactly one fenced block in this form:\n"
        "```worker-evidence\n"
        '{"pr_url": "https://github.com/OWNER/REPO/pull/N", '
        f'"branch": "{task.branch}", "commit": "<40 lowercase hex>", '
        '"tests": ["command: result"], "blockers": []}\n'
        "```\n"
    )


def build_start_request(task: WorkerTask) -> dict[str, Any]:
    """Build the pinned upstream StartConversationRequest payload."""
    return {
        "workspace": {"kind": "LocalWorkspace", "working_dir": task.repo_path},
        "worktree": True,
        "worktree_options": {
            "base": "default_branch",
            "branch_prefix": task.branch_prefix,
        },
        "conversation_id": str(task.conversation_id),
        "agent_profile_id": str(task.profile_id),
        "initial_message": {
            "role": "user",
            "content": [{"type": "text", "text": build_prompt(task)}],
        },
        "max_iterations": task.max_iterations,
        "max_budget_per_run": task.max_budget_per_run,
        "conversation_runtime": "local",
        "autotitle": task.autotitle,
        "tags": task.tags,
    }


def parse_pr_evidence(text: str, task: WorkerTask) -> PullRequestEvidence:
    """Parse the final worker evidence block and bind it to this task."""
    if not isinstance(text, str):
        raise WorkerError("worker final response is not text")
    blocks = _EVIDENCE_RE.findall(text)
    if not blocks:
        raise WorkerError("worker final response has no worker-evidence block")
    try:
        payload = json.loads(blocks[-1])
    except ValueError:
        raise WorkerError("worker-evidence block is not valid JSON") from None
    if not isinstance(payload, dict):
        raise WorkerError("worker-evidence block must be an object")

    pr_url = _safe_line(payload.get("pr_url"), name="pr_url", limit=300)
    match = _PR_RE.fullmatch(pr_url)
    if not match:
        raise WorkerError("pr_url must be an exact https://github.com pull request URL")
    owner, repo, _number = match.groups()
    if f"{owner}/{repo}".lower() != task.repository.lower():
        raise WorkerError("pr_url is for a different repository")

    branch = _safe_line(payload.get("branch"), name="branch", limit=300)
    if branch != task.branch:
        raise WorkerError("worker reported a different branch")

    commit = payload.get("commit")
    if not isinstance(commit, str) or not _COMMIT_RE.fullmatch(commit):
        raise WorkerError("commit must be 40 lowercase hexadecimal characters")

    tests = payload.get("tests")
    if not isinstance(tests, list) or not tests or len(tests) > 50:
        raise WorkerError("tests must be a non-empty list of up to 50 entries")
    tests = tuple(
        redact_text(_safe_line(item, name="test result", limit=_MAX_TEXT)) for item in tests
    )

    blockers = payload.get("blockers")
    if not isinstance(blockers, list) or len(blockers) > 50:
        raise WorkerError("blockers must be a list of up to 50 entries")
    blockers = tuple(
        redact_text(_safe_line(item, name="blocker", limit=_MAX_BLOCKER)) for item in blockers
    )

    return PullRequestEvidence(
        pr_url=pr_url,
        branch=branch,
        commit=commit,
        tests=tests,
        blockers=blockers,
    )


class WorkerClient:
    """Minimal OpenHands conversation client with native worktree dispatch."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        max_concurrent: int = 2,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = _safe_url(base_url)
        if not isinstance(api_key, str) or not api_key or api_key != api_key.strip():
            raise WorkerError("OpenHands session API key is required")
        if not isinstance(max_concurrent, int) or not 1 <= max_concurrent <= 8:
            raise WorkerError("max_concurrent must be between 1 and 8")
        self._concurrency = asyncio.Semaphore(max_concurrent)
        self._client = httpx2.AsyncClient(
            base_url=self._base_url,
            headers={"X-Session-API-Key": api_key},
            transport=transport,
            follow_redirects=False,
        )

    async def __aenter__(self) -> WorkerClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, dict[str, Any]]:
        try:
            response = await self._client.request(method, path, json=body, timeout=timeout)
        except httpx2.TimeoutException:
            raise _HTTPTimeout("OpenHands request timed out") from None
        except httpx2.HTTPError as exc:
            raise WorkerError(f"OpenHands request failed ({type(exc).__name__})") from None
        if 300 <= response.status_code < 400:
            raise WorkerError("OpenHands redirect refused")
        if not 200 <= response.status_code < 300:
            raise WorkerError(f"OpenHands returned HTTP {response.status_code}")
        if len(response.content) > _MAX_RESPONSE_BYTES:
            raise WorkerError("OpenHands response too large")
        try:
            data = response.json()
        except ValueError:
            raise WorkerError("OpenHands returned invalid JSON") from None
        if not isinstance(data, dict):
            raise WorkerError("OpenHands returned an invalid object")
        return response.status_code, data

    async def preflight(self, task: WorkerTask) -> dict[str, str]:
        """Check the stored ACP profile and exact model before dispatch."""
        _, listing = await self._request("GET", "/api/agent-profiles", timeout=15.0)
        profiles = listing.get("profiles")
        if not isinstance(profiles, list):
            raise WorkerError("OpenHands returned an invalid agent profile list")
        wanted = str(task.profile_id)
        matches = [item for item in profiles if isinstance(item, dict) and item.get("id") == wanted]
        if len(matches) != 1:
            raise WorkerError("the exact ACP agent profile is not available")
        summary = matches[0]
        if summary.get("agent_kind") != "acp":
            raise WorkerError("the selected agent profile is not ACP")
        name = _safe_line(summary.get("name"), name="profile name", limit=128)

        _, detail = await self._request(
            "GET", f"/api/agent-profiles/{quote(name, safe='')}", timeout=15.0
        )
        profile = detail.get("profile")
        if not isinstance(profile, dict):
            raise WorkerError("OpenHands returned an invalid agent profile")
        if profile.get("id") != wanted or profile.get("agent_kind") != "acp":
            raise WorkerError("the selected ACP agent profile does not match")
        if profile.get("acp_server") != task.expected_acp_server:
            raise WorkerError("the ACP server does not match the requested profile")
        if profile.get("acp_model") != task.expected_model:
            raise WorkerError("the ACP profile model does not exactly match")
        return {
            "name": name,
            "id": wanted,
            "acp_server": task.expected_acp_server,
            "acp_model": task.expected_model,
        }

    async def start(self, task: WorkerTask) -> WorkerDispatch:
        """Start or idempotently reuse the task's native conversation."""
        await self.preflight(task)
        body = build_start_request(task)
        try:
            async with self._concurrency:
                status, info = await self._request(
                    "POST",
                    "/api/conversations",
                    body=body,
                    timeout=task.timeout_seconds,
                )
        except _HTTPTimeout:
            # The POST may have committed before the response was lost. Keep
            # the client-generated id so the caller can query it before retry.
            raise WorkerTimeout(
                "OpenHands start timed out; query the conversation before retrying",
                task.conversation_id,
            ) from None
        if status not in (200, 201):
            raise WorkerError(f"unexpected OpenHands start status {status}")
        try:
            dispatch = self._validate_info(task, info, created=status == 201)
        except WorkerError:
            # Only interrupt a conversation this request created. A 200 means
            # the id belongs to an existing conversation; never stop someone
            # else's work because a caller reused the wrong id.
            if status == 201:
                await self._safe_interrupt(task.conversation_id)
            raise
        return dispatch

    async def status(self, task: WorkerTask, *, verify_pr: bool = False) -> WorkerStatus:
        """Read native status and, when terminal, validate the PR evidence."""
        _, info = await self._request(
            "GET", f"/api/conversations/{task.conversation_id}", timeout=20.0
        )
        self._validate_common(task, info)
        raw_value = info.get("execution_status")
        raw_status = raw_value if isinstance(raw_value, str) else "unknown"
        state = map_status(raw_status)
        terminal = raw_status in _TERMINAL

        evidence: PullRequestEvidence | None = None
        evidence_error: str | None = None
        pr_verification: dict[str, Any] | None = None
        if terminal:
            _, final = await self._request(
                "GET",
                f"/api/conversations/{task.conversation_id}/agent_final_response",
                timeout=20.0,
            )
            response = final.get("response")
            if not isinstance(response, str):
                evidence_error = "OpenHands returned no worker final response"
            else:
                try:
                    evidence = parse_pr_evidence(response, task)
                except WorkerError as exc:
                    evidence_error = str(exc)
        if verify_pr and evidence is not None:
            try:
                pr_verification = await self._verify_pr(evidence)
            except WorkerError as exc:
                pr_verification = {"verified": False, "error": str(exc)}

        return WorkerStatus(
            conversation_id=task.conversation_id,
            branch=task.branch,
            workspace=self._workspace(info),
            model=self._model(info),
            acp_server=self._acp_server(info),
            raw_status=raw_status,
            state=state,
            terminal=terminal,
            pr=evidence,
            pr_verification=pr_verification,
            evidence_error=evidence_error,
        )

    async def stop(self, conversation_id: UUID, *, timeout: float = 20.0) -> str:
        """Interrupt a conversation. Native worktrees are not deleted here."""
        status, _ = await self._request(
            "POST", f"/api/conversations/{conversation_id}/interrupt", timeout=timeout
        )
        if status != 200:
            raise WorkerError(f"unexpected OpenHands stop status {status}")
        return "paused"

    async def _safe_interrupt(self, conversation_id: UUID) -> None:
        try:
            await self.stop(conversation_id)
        except WorkerError:
            pass

    def _validate_info(
        self, task: WorkerTask, info: dict[str, Any], *, created: bool
    ) -> WorkerDispatch:
        self._validate_common(task, info)
        raw_status = str(info.get("execution_status"))
        return WorkerDispatch(
            conversation_id=task.conversation_id,
            branch=task.branch,
            workspace=self._workspace(info),
            model=self._model(info),
            acp_server=self._acp_server(info),
            created=created,
            raw_status=raw_status,
            state=map_status(raw_status),
        )

    def _validate_common(self, task: WorkerTask, info: dict[str, Any]) -> None:
        if info.get("id") != str(task.conversation_id):
            raise WorkerError("OpenHands returned a different conversation id")
        tags = info.get("tags")
        if not isinstance(tags, dict) or any(
            tags.get(key) != value for key, value in task.tags.items()
        ):
            raise WorkerError("conversation id is already used by a different task")
        if self._model(info) != task.expected_model:
            raise WorkerError("conversation model does not exactly match")
        if self._acp_server(info) != task.expected_acp_server:
            raise WorkerError("conversation ACP server does not exactly match")
        workspace = self._workspace(info)
        if str(task.conversation_id) not in Path(workspace).parts:
            raise WorkerError("conversation is not in its native worktree")
        if Path(workspace).resolve() == Path(task.repo_path).resolve():
            raise WorkerError("native worktree was not created")

    @staticmethod
    def _workspace(info: dict[str, Any]) -> str:
        workspace = info.get("workspace")
        if not isinstance(workspace, dict) or workspace.get("kind") != "LocalWorkspace":
            raise WorkerError("OpenHands returned an invalid workspace")
        working_dir = workspace.get("working_dir")
        if not isinstance(working_dir, str) or not Path(working_dir).is_absolute():
            raise WorkerError("OpenHands returned an invalid workspace path")
        return working_dir

    @staticmethod
    def _model(info: dict[str, Any]) -> str:
        agent = info.get("agent")
        if not isinstance(agent, dict) or agent.get("kind") != "ACPAgent":
            raise WorkerError("the conversation agent is not ACP")
        model = agent.get("acp_model")
        if not isinstance(model, str) or not model:
            raise WorkerError("the conversation has no exact ACP model")
        return model

    @staticmethod
    def _acp_server(info: dict[str, Any]) -> str:
        agent = info.get("agent")
        if not isinstance(agent, dict):
            raise WorkerError("the conversation has no agent")
        server = agent.get("acp_server")
        if not isinstance(server, str) or not server:
            raise WorkerError("the conversation has no exact ACP server")
        return server

    async def _verify_pr(self, evidence: PullRequestEvidence) -> dict[str, Any]:
        match = _PR_RE.fullmatch(evidence.pr_url)
        if not match:
            raise WorkerError("pr_url is invalid")
        owner, repo, number = match.groups()
        _, pr = await self._request(
            "GET",
            f"/api/git/repositories/{quote(owner, safe='')}/{quote(repo, safe='')}"
            f"/pull-requests/{number}?provider=github",
            timeout=20.0,
        )
        if pr.get("url") != evidence.pr_url:
            raise WorkerError("OpenHands returned a different pull request")
        if pr.get("head_sha") != evidence.commit:
            raise WorkerError("the pull request head does not match the reported commit")
        checks = pr.get("checks")
        state = pr.get("state")
        if not isinstance(checks, str) or not isinstance(state, str):
            raise WorkerError("OpenHands returned an invalid pull request status")
        return {
            "verified": True,
            "state": state,
            "checks": checks,
            "draft": bool(pr.get("draft")),
            "head_sha": pr["head_sha"],
        }
