"""Source-only OpenHands worker dispatch for one issue/branch/worktree/conversation.

The upstream agent server owns worktree creation, conversation lifecycle and
cleanup. This module creates the native conversation without its task, verifies
the worktree/model/effort, selects the requested ACP model/effort natively, and
only then submits the task. It scopes list/status/dispatch/cancel to one
approved repository and never starts another runtime, queue or conversation
store.

Schema reference: OpenHands software-agent-sdk v1.62.0
(commit 504a88cab0fb48ee5226238ad7b8f1d865fa84a8). The fields used here are in
``openhands-sdk/openhands/sdk/conversation/request.py`` and the HTTP routes in
``openhands-agent-server/openhands/agent_server/conversation_router.py``.
Live search has pagination but no repository filter, so this module filters the
native ``kulerepo`` tag with a hard page bound.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import shlex
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit
from uuid import UUID, uuid4
from weakref import WeakValueDictionary

import httpx2

from .redact import redact_text

# The issue asked for ``opencode-go/deepseek-v4.1-flash-1017``. The selectable
# OpenCode model ID is ``opencode-go/deepseek-v4.1-flash``; "DeepSeek V4.1
# Flash 1017" is its display name. Never substitute a display name or a
# different (possibly paid) model.
DEFAULT_MODEL = "opencode-go/deepseek-v4.1-flash"
DEFAULT_ACP_SERVER = "opencode"

PINNED_SDK_TAG = "v1.62.0"
PINNED_SDK_COMMIT = "504a88cab0fb48ee5226238ad7b8f1d865fa84a8"

API_KEY_ENV = "KULE_OPENHANDS_API_KEY"
API_URL_ENV = "KULE_OPENHANDS_API_URL"

# Canonical native scope tag. Existing pre-tag conversations are never inferred.
REPOSITORY_TAG = "kulerepo"

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_TASK_BYTES = 20_000
_MAX_TEXT = 300
_MAX_BLOCKER = 500
_MAX_SECRETS_BYTES = 64 * 1024
_MAX_SEARCH_PAGES = 100
_MAX_SEARCH_RESULTS = 1000
_MAX_EFFORT = 100

_REPO_COMPONENT = r"(?!\.{1,2}(?:/|#|$))[A-Za-z0-9_.-]+"
_ISSUE_RE = re.compile(rf"^{_REPO_COMPONENT}/{_REPO_COMPONENT}#[1-9][0-9]*$")
_REPO_RE = re.compile(rf"^{_REPO_COMPONENT}/{_REPO_COMPONENT}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_BRANCH_PREFIX_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._/-]*)?$")
_PR_RE = re.compile(
    rf"^https://github\.com/({_REPO_COMPONENT})/({_REPO_COMPONENT})/pull/([1-9][0-9]*)$"
)
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_EVIDENCE_RE = re.compile(
    r"```worker-evidence[ \t]*\r?\n(\{.*?\})\r?\n```",
    re.DOTALL,
)

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

BranchReader = Callable[[str], Awaitable[str | None]]
"""Read the actual checked-out branch for a workspace path.

The pinned conversation API has no branch field. Live adapters can supply a
read-only workspace reader so status/start verify the branch instead of
trusting the worker or the derived name.
"""


class WorkerError(RuntimeError):
    """A safe, bounded worker-dispatch error."""


class WorkerTimeout(WorkerError):
    """The start request timed out after possibly creating the conversation."""

    def __init__(self, message: str, conversation_id: UUID) -> None:
        super().__init__(message)
        self.conversation_id = conversation_id


class WorkerRunPending(WorkerError):
    """The task was saved but no run slot was admitted after bounded retries.

    A later identical dispatch may retry ``/run`` without reposting the task.
    """

    def __init__(self, conversation_id: UUID) -> None:
        super().__init__("the task was saved but no run slot was admitted; retry the conversation")
        self.conversation_id = conversation_id


class WorkerHTTPError(WorkerError):
    """A non-2xx OpenHands response; status is preserved for recovery."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"OpenHands returned HTTP {status_code}")
        self.status_code = status_code


class WorkerResponseError(WorkerError):
    """A 2xx response whose body was invalid or exceeded the bound."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


class _HTTPTimeout(WorkerError):
    """Internal transport timeout with no conversation assumptions."""


@dataclass(frozen=True)
class WorkerTask:
    """One independent issue worker, with a unique native conversation.

    ``repository`` must match the issue's owner/repo and be present in the
    client's approved repository-to-path mapping. ``conversation_id`` is
    generated once per dispatch. Reuse it only for an identical retry; branch,
    effort, model, profile, issue and task are part of the native identity.

    ``secrets`` is an opaque OpenHands ``SecretSource`` mapping supplied by the
    trusted adapter for per-run model selection. It is never logged or included
    in status output.
    """

    issue_ref: str
    repository: str
    task: str
    profile_id: UUID
    expected_model: str = DEFAULT_MODEL
    expected_effort: str | None = None
    expected_acp_server: str = DEFAULT_ACP_SERVER
    branch_prefix: str = "openhands/"
    conversation_id: UUID = field(default_factory=uuid4)
    max_iterations: int = 80
    max_budget_per_run: float = 2.0
    timeout_seconds: float = 60.0
    autotitle: bool = False
    allow_model_override: bool = True
    secrets: Mapping[str, Mapping[str, Any]] = field(default_factory=dict, repr=False)

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
        _canonical_repo(self.repository)
        issue_repo, _, _ = self.issue_ref.partition("#")
        if issue_repo.lower() != self.repository.lower():
            raise WorkerError("issue_ref repository must match repository")
        if not isinstance(self.task, str) or not self.task.strip():
            raise WorkerError("task must not be empty")
        if len(self.task.encode("utf-8")) > _MAX_TASK_BYTES:
            raise WorkerError(f"task must be at most {_MAX_TASK_BYTES} UTF-8 bytes")
        if not isinstance(self.profile_id, UUID):
            raise WorkerError("profile_id must be a UUID")
        if not isinstance(self.conversation_id, UUID):
            raise WorkerError("conversation_id must be a UUID")
        validate_model(self.expected_model)
        if self.expected_effort is not None:
            _validate_effort(self.expected_effort)
        if self.expected_acp_server not in {"opencode", "codex", "claude-code", "custom"}:
            raise WorkerError("expected_acp_server is not a supported ACP profile")
        _validate_branch_prefix(self.branch_prefix)
        _validate_git_ref(self.branch)
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
        if not isinstance(self.allow_model_override, bool):
            raise WorkerError("allow_model_override must be a bool")
        _validate_secrets(self.secrets)
        object.__setattr__(self, "secrets", dict(self.secrets))

    @property
    def repository_key(self) -> str:
        return self.repository.lower()

    @property
    def branch(self) -> str:
        """The branch the upstream worktree planner creates: prefix + id."""
        return f"{self.branch_prefix}{self.conversation_id}"

    @property
    def task_digest(self) -> str:
        return hashlib.sha256(self.task.encode("utf-8")).hexdigest()[:16]

    @property
    def tags(self) -> dict[str, str]:
        """Native identity used for scope and safe idempotency."""
        return {
            REPOSITORY_TAG: self.repository_key,
            "kuleissue": self.issue_ref,
            "kuletask": self.task_digest,
            "kulemodel": self.expected_model,
            "kuleprofile": str(self.profile_id),
            "kulebranch": self.branch,
            "kuleeffort": self.expected_effort or "-",
        }


@dataclass(frozen=True)
class PullRequestEvidence:
    pr_url: str | None
    branch: str | None
    commit: str | None
    tests: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "pr_url": self.pr_url,
            "branch": self.branch,
            "commit": self.commit,
            "tests": list(self.tests),
            "blockers": list(self.blockers),
        }


@dataclass(frozen=True)
class ModelPreflight:
    """The exact profile/model/effort source selected before dispatch."""

    profile_name: str
    profile_id: UUID
    mode: str
    acp_server: str
    model: str
    effort: str | None = None
    switch_model: bool = False
    switch_effort: bool = False
    agent_settings: dict[str, Any] | None = None
    available_models: tuple[str, ...] = ()
    # ``None`` means the profile does not restrict names. An explicit tuple
    # filters request secrets before they reach the conversation.
    secret_names: tuple[str, ...] | None = None


@dataclass(frozen=True)
class WorkerDispatch:
    repository: str
    conversation_id: UUID
    branch: str
    workspace: str
    model: str
    effective_model: str | None
    effort: str | None
    effective_effort: str | None
    acp_server: str
    created: bool
    raw_status: str
    state: str
    branch_verified: bool | None = None
    model_verified: bool = False
    effort_verified: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "conversation_id": str(self.conversation_id),
            "branch": self.branch,
            "workspace": self.workspace,
            "model": self.model,
            "effective_model": self.effective_model,
            "effort": self.effort,
            "effective_effort": self.effective_effort,
            "acp_server": self.acp_server,
            "created": self.created,
            "status": self.raw_status,
            "state": self.state,
            "branch_verified": self.branch_verified,
            "model_verified": self.model_verified,
            "effort_verified": self.effort_verified,
        }


@dataclass(frozen=True)
class WorkerStatus:
    repository: str
    conversation_id: UUID
    branch: str
    workspace: str
    model: str
    effective_model: str | None
    effort: str | None
    effective_effort: str | None
    acp_server: str
    raw_status: str
    state: str
    terminal: bool
    pr: PullRequestEvidence | None = None
    pr_verification: dict[str, Any] | None = None
    evidence_error: str | None = None
    branch_verified: bool | None = None
    actual_branch: str | None = None
    branch_error: str | None = None
    model_verified: bool = False
    model_error: str | None = None
    effort_verified: bool | None = None
    effort_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "conversation_id": str(self.conversation_id),
            "branch": self.branch,
            "workspace": self.workspace,
            "model": self.model,
            "effective_model": self.effective_model,
            "effort": self.effort,
            "effective_effort": self.effective_effort,
            "acp_server": self.acp_server,
            "status": self.raw_status,
            "state": self.state,
            "terminal": self.terminal,
            "pr": self.pr.as_dict() if self.pr else None,
            "pr_verification": self.pr_verification,
            "evidence_error": self.evidence_error,
            "branch_verified": self.branch_verified,
            "actual_branch": self.actual_branch,
            "branch_error": self.branch_error,
            "model_verified": self.model_verified,
            "model_error": self.model_error,
            "effort_verified": self.effort_verified,
            "effort_error": self.effort_error,
        }


@dataclass(frozen=True)
class WorkerStop:
    conversation_id: UUID
    acknowledged: bool
    raw_status: str
    state: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": str(self.conversation_id),
            "acknowledged": self.acknowledged,
            "status": self.raw_status,
            "state": self.state,
        }


@dataclass(frozen=True)
class ScopedConversation:
    repository: str
    conversation_id: UUID
    raw_status: str
    state: str
    title: str | None
    model: str | None
    workspace: str | None
    legacy: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "conversation_id": str(self.conversation_id),
            "status": self.raw_status,
            "state": self.state,
            "title": self.title,
            "model": self.model,
            "workspace": self.workspace,
            "legacy": self.legacy,
        }


@dataclass(frozen=True)
class ScopedConversationList:
    """Bounded repository-scoped result; unclassified ids are not returned."""

    repository: str
    items: tuple[ScopedConversation, ...]
    unclassified_count: int
    pages: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "items": [item.as_dict() for item in self.items],
            "unclassified_count": self.unclassified_count,
            "pages": self.pages,
        }


def validate_model(model: str) -> str:
    """Require one exact selectable model ID; never a prefix, glob or alias."""
    if not isinstance(model, str) or not model or model != model.strip():
        raise WorkerError("expected_model must be one exact non-empty model ID")
    if len(model) > 200 or not _MODEL_RE.fullmatch(model) or ".." in model:
        raise WorkerError("expected_model is not a valid model ID")
    return model


def _validate_effort(effort: str) -> str:
    if (
        not isinstance(effort, str)
        or not effort
        or effort != effort.strip()
        or len(effort) > _MAX_EFFORT
        or not _MODEL_RE.fullmatch(effort)
        or ".." in effort
    ):
        raise WorkerError("expected_effort is not a valid effort ID")
    return effort


def map_status(raw: str) -> str:
    """Map a native execution status to the worker's small state vocabulary."""
    if not isinstance(raw, str):
        return "unknown"
    return _STATUS_MAP.get(raw, "unknown")


def _validate_branch_prefix(prefix: str) -> None:
    if not isinstance(prefix, str) or len(prefix) > 200:
        raise WorkerError("branch_prefix is invalid")
    if not _BRANCH_PREFIX_RE.fullmatch(prefix) or prefix == "" or ".." in prefix or "@{" in prefix:
        raise WorkerError("branch_prefix is not a safe git branch prefix")
    parts = prefix.split("/")
    for index, part in enumerate(parts):
        if part == "":
            # A single trailing slash is the normal prefix delimiter.
            if index == len(parts) - 1 and prefix.endswith("/"):
                continue
            raise WorkerError("branch_prefix is not a safe git branch prefix")
        if part.startswith(".") or part.endswith(".lock") or part.endswith("."):
            raise WorkerError("branch_prefix is not a safe git branch prefix")


def _validate_git_ref(ref: str) -> None:
    """Apply Git's ref-name rules to the complete prefix+conversation branch."""
    if (
        not isinstance(ref, str)
        or not ref
        or len(ref) > 255
        or not _MODEL_RE.fullmatch(ref)
        or ref.startswith("/")
        or ref.endswith("/")
        or "//" in ref
        or ".." in ref
        or "@{" in ref
        or ref == "@"
    ):
        raise WorkerError("branch is not a valid git ref")
    for part in ref.split("/"):
        if not part or part.startswith(".") or part.endswith(".lock") or part.endswith("."):
            raise WorkerError("branch is not a valid git ref")


def _validate_secrets(secrets: Mapping[str, Mapping[str, Any]]) -> None:
    if not isinstance(secrets, Mapping) or len(secrets) > 20:
        raise WorkerError("secrets must be a mapping of at most 20 entries")
    for name, value in secrets.items():
        if not isinstance(name, str) or not name or len(name) > 128:
            raise WorkerError("secret names must be non-empty strings")
        if not isinstance(value, Mapping):
            raise WorkerError("secret values must be OpenHands SecretSource objects")
    try:
        size = len(json.dumps(dict(secrets), sort_keys=True).encode("utf-8"))
    except (TypeError, ValueError):
        raise WorkerError("secrets must be JSON serializable") from None
    if size > _MAX_SECRETS_BYTES:
        raise WorkerError("secrets are too large")


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


def _canonical_repo(repository: str) -> str:
    if not isinstance(repository, str) or len(repository) > 150 or repository.count("/") != 1:
        raise WorkerError("repository must look like owner/name")
    owner, name = repository.split("/", 1)
    if owner in {".", ".."} or name in {".", ".."}:
        raise WorkerError("repository must not contain dot path components")
    if not _REPO_RE.fullmatch(repository):
        raise WorkerError("repository must look like owner/name")
    return repository.lower()


def _approved_path(path: Any, repository: str) -> str:
    if not isinstance(path, str) or not path or "\x00" in path or len(path) > 1024:
        raise WorkerError(f"approved repository path is invalid for {repository}")
    if not Path(path).is_absolute() or Path(path) == Path("/"):
        raise WorkerError(f"approved repository path is invalid for {repository}")
    return path


def _normalize_repositories(repositories: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(repositories, Mapping) or not repositories:
        raise WorkerError("an approved repository-to-path mapping is required")
    if len(repositories) > 100:
        raise WorkerError("too many approved repositories")
    normalized: dict[str, str] = {}
    for repository, path in repositories.items():
        key = _canonical_repo(repository)
        if key in normalized:
            raise WorkerError("approved repository mapping contains duplicates")
        normalized[key] = _approved_path(path, key)
    return normalized


def _normalize_legacy(
    legacy: Mapping[UUID | str, str] | None, repositories: Mapping[str, str]
) -> dict[UUID, str]:
    """Explicit operator mapping for pre-tag conversations; never inferred."""
    if legacy is None:
        return {}
    if not isinstance(legacy, Mapping) or len(legacy) > 100:
        raise WorkerError("legacy repository mapping must be a bounded mapping")
    normalized: dict[UUID, str] = {}
    for raw_id, repository in legacy.items():
        conversation_id = _parse_uuid(raw_id)
        if conversation_id is None:
            raise WorkerError("legacy mapping contains an invalid conversation id")
        key = _canonical_repo(repository)
        if key not in repositories:
            raise WorkerError("legacy mapping points at an unapproved repository")
        if conversation_id in normalized:
            raise WorkerError("legacy mapping contains duplicate conversation ids")
        normalized[conversation_id] = key
    return normalized


def _parse_uuid(value: Any) -> UUID | None:
    if isinstance(value, UUID):
        return value
    if isinstance(value, str):
        try:
            return UUID(value)
        except ValueError:
            return None
    return None


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
        "End your final message with exactly one fenced block. If you opened a PR:\n"
        "```worker-evidence\n"
        '{"pr_url": "https://github.com/OWNER/REPO/pull/N", '
        f'"branch": "{task.branch}", "commit": "<40 lowercase hex>", '
        '"tests": ["command: result"], "blockers": []}\n'
        "```\n"
        "If no PR exists because you are blocked, use a blocker-only block:\n"
        "```worker-evidence\n"
        '{"blockers": ["specific reason and next owner action"]}\n'
        "```\n"
    )


def _acp_command_tokens(value: Any) -> list[str] | None:
    """Return a validated argv, or ``None`` for an unset/blank built-in command."""
    if value is None:
        return None
    if isinstance(value, str):
        if not value.strip():
            return None
        try:
            tokens = shlex.split(value)
        except ValueError:
            raise WorkerError("the profile ACP command is not parseable") from None
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        tokens = list(value)
    else:
        raise WorkerError("the profile ACP command is invalid")
    if not tokens:
        return None
    # A whitespace-only or empty executable would be passed verbatim by the
    # pinned SDK instead of selecting the provider default.
    if not tokens[0].strip():
        raise WorkerError("the profile ACP command is invalid")
    return tokens


def _agent_settings_from_profile(
    profile: Mapping[str, Any], target_model: str, target_effort: str | None
) -> dict[str, Any]:
    """Derive a per-conversation ACP settings payload without mutating the profile."""
    settings: dict[str, Any] = {
        "agent_kind": "acp",
        "acp_server": profile.get("acp_server"),
        "acp_model": target_model,
    }
    if target_effort is not None:
        settings["acp_effort"] = target_effort
    for key in ("acp_effort", "acp_session_mode", "acp_prompt_timeout", "acp_startup_timeout"):
        if key in settings:
            continue
        if profile.get(key) is not None:
            settings[key] = profile[key]
    command = _acp_command_tokens(profile.get("acp_command"))
    if command is not None:
        settings["acp_command"] = command
    arguments = profile.get("acp_args")
    if arguments is not None:
        if isinstance(arguments, list) and all(isinstance(item, str) for item in arguments):
            settings["acp_args"] = list(arguments)
        else:
            raise WorkerError("the profile ACP arguments are invalid")
    if profile.get("acp_server") == "custom" and not settings.get("acp_command"):
        raise WorkerError("a custom ACP profile requires an explicit command")
    for key in ("acp_isolate_data_dir", "acp_file_secrets"):
        if profile.get(key) is not None:
            settings[key] = profile[key]
    return settings


def _effort_values(discovery: Mapping[str, Any], model: str) -> tuple[str, ...]:
    efforts = discovery.get("efforts_by_model")
    if not isinstance(efforts, dict):
        return ()
    values = efforts.get(model)
    if not isinstance(values, list):
        return ()
    return tuple(
        item.get("value")
        for item in values
        if isinstance(item, dict) and isinstance(item.get("value"), str)
    )


def build_start_request(
    task: WorkerTask, repo_path: str, preflight: ModelPreflight
) -> dict[str, Any]:
    """Build the pinned StartConversationRequest without an initial task message."""
    body: dict[str, Any] = {
        "workspace": {"kind": "LocalWorkspace", "working_dir": repo_path},
        "worktree": True,
        "worktree_options": {
            "base": "default_branch",
            "branch_prefix": task.branch_prefix,
        },
        "conversation_id": str(task.conversation_id),
        "max_iterations": task.max_iterations,
        "max_budget_per_run": task.max_budget_per_run,
        "conversation_runtime": "local",
        "autotitle": task.autotitle,
        "tags": task.tags,
    }
    if preflight.mode == "profile":
        body["agent_profile_id"] = str(preflight.profile_id)
    else:
        if not preflight.agent_settings:
            raise WorkerError("model override has no derived agent settings")
        body["agent_settings"] = dict(preflight.agent_settings)
    if task.secrets:
        if preflight.secret_names is None:
            body["secrets"] = dict(task.secrets)
        else:
            allowed = set(preflight.secret_names)
            secrets = {name: value for name, value in task.secrets.items() if name in allowed}
            if secrets:
                body["secrets"] = secrets
    return body


def build_task_message(task: WorkerTask) -> dict[str, Any]:
    return {
        "role": "user",
        "content": [{"type": "text", "text": build_prompt(task)}],
        "run": True,
    }


def parse_pr_evidence(text: str, task: WorkerTask) -> PullRequestEvidence:
    """Parse the last worker-evidence block and bind a PR report to this task."""
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

    raw_blockers = payload.get("blockers", [])
    if not isinstance(raw_blockers, list) or len(raw_blockers) > 50:
        raise WorkerError("blockers must be a list of up to 50 entries")
    blockers = tuple(
        redact_text(_safe_line(item, name="blocker", limit=_MAX_BLOCKER)) for item in raw_blockers
    )

    if not any(payload.get(key) is not None for key in ("pr_url", "branch", "commit", "tests")):
        if blockers:
            return PullRequestEvidence(
                pr_url=None, branch=None, commit=None, tests=(), blockers=blockers
            )
        raise WorkerError("worker evidence has neither a PR nor a blocker")

    pr_url = _safe_line(payload.get("pr_url"), name="pr_url", limit=300)
    match = _PR_RE.fullmatch(pr_url)
    if not match:
        raise WorkerError("pr_url must be an exact https://github.com pull request URL")
    owner, repo, _number = match.groups()
    try:
        reported_repository = _canonical_repo(f"{owner}/{repo}")
    except WorkerError:
        raise WorkerError("pr_url is not a valid repository URL") from None
    if reported_repository != task.repository_key:
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
    return PullRequestEvidence(
        pr_url=pr_url,
        branch=branch,
        commit=commit,
        tests=tests,
        blockers=blockers,
    )


class WorkerClient:
    """Minimal repository-scoped OpenHands conversation client."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        repositories: Mapping[str, str],
        legacy_repository_by_id: Mapping[UUID | str, str] | None = None,
        max_concurrent_starts: int = 2,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = _safe_url(base_url)
        if not isinstance(api_key, str) or not api_key or api_key != api_key.strip():
            raise WorkerError("OpenHands session API key is required")
        self._repositories = _normalize_repositories(repositories)
        self._legacy = _normalize_legacy(legacy_repository_by_id, self._repositories)
        if (
            not isinstance(max_concurrent_starts, int)
            or isinstance(max_concurrent_starts, bool)
            or not 1 <= max_concurrent_starts <= 8
        ):
            raise WorkerError("max_concurrent_starts must be between 1 and 8")
        self._start_slots = asyncio.Semaphore(max_concurrent_starts)
        self._start_locks: WeakValueDictionary[UUID, asyncio.Lock] = WeakValueDictionary()
        self._client = httpx2.AsyncClient(
            base_url=self._base_url,
            headers={"X-Session-API-Key": api_key},
            transport=transport,
            follow_redirects=False,
            trust_env=False,
        )

    async def __aenter__(self) -> WorkerClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def _repo_path(self, repository: str) -> str:
        key = _canonical_repo(repository)
        path = self._repositories.get(key)
        if path is None:
            raise WorkerError("repository is not approved for worker dispatch")
        return path

    def _start_lock(self, conversation_id: UUID) -> asyncio.Lock:
        lock = self._start_locks.get(conversation_id)
        if lock is None:
            lock = asyncio.Lock()
            self._start_locks[conversation_id] = lock
        return lock

    def _scope_of(self, info: Mapping[str, Any]) -> tuple[str | None, bool]:
        """Return (approved repository key, explicit legacy flag).

        A missing or foreign ``kulerepo`` tag is never inferred. Only an
        operator-supplied legacy id mapping can classify a pre-tag conversation.
        """
        tags = info.get("tags")
        tag = tags.get(REPOSITORY_TAG) if isinstance(tags, dict) else None
        if isinstance(tag, str) and tag:
            try:
                key = _canonical_repo(tag)
            except WorkerError:
                return None, False
            if key in self._repositories:
                return key, False
            return None, False
        conversation_id = _parse_uuid(info.get("id"))
        if conversation_id is not None and conversation_id in self._legacy:
            return self._legacy[conversation_id], True
        return None, False

    async def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> tuple[int, dict[str, Any]]:
        try:
            async with self._client.stream(method, path, json=body, timeout=timeout) as response:
                status_code = response.status_code
                if 300 <= status_code < 400:
                    raise WorkerHTTPError(status_code)
                if not 200 <= status_code < 300:
                    raise WorkerHTTPError(status_code)
                length = response.headers.get("content-length")
                if length is not None:
                    try:
                        declared = int(length)
                    except ValueError:
                        raise WorkerResponseError(
                            status_code, "OpenHands returned an invalid content length"
                        ) from None
                    if declared > _MAX_RESPONSE_BYTES:
                        raise WorkerResponseError(status_code, "OpenHands response too large")
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > _MAX_RESPONSE_BYTES:
                        raise WorkerResponseError(status_code, "OpenHands response too large")
        except httpx2.TimeoutException:
            raise _HTTPTimeout("OpenHands request timed out") from None
        except httpx2.HTTPError as exc:
            raise WorkerError(f"OpenHands request failed ({type(exc).__name__})") from None
        try:
            data = json.loads(content)
        except (UnicodeDecodeError, ValueError):
            raise WorkerResponseError(status_code, "OpenHands returned invalid JSON") from None
        if not isinstance(data, dict):
            raise WorkerResponseError(status_code, "OpenHands returned an invalid object")
        return status_code, data

    async def preflight(self, task: WorkerTask) -> ModelPreflight:
        """Verify approved repo, stored ACP profile and exact model/effort."""
        self._repo_path(task.repository)
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

        secret_refs = profile.get("secret_refs")
        if secret_refs is None:
            secret_names = None
        elif isinstance(secret_refs, list) and all(
            isinstance(item, str) and item for item in secret_refs
        ):
            secret_names = tuple(secret_refs)
        else:
            raise WorkerError("the ACP profile secret references are invalid")

        profile_model = profile.get("acp_model")
        profile_effort = profile.get("acp_effort")
        model_matches = profile_model == task.expected_model
        effort_matches = task.expected_effort is None or profile_effort == task.expected_effort
        if model_matches and effort_matches:
            return ModelPreflight(
                profile_name=name,
                profile_id=task.profile_id,
                mode="profile",
                acp_server=task.expected_acp_server,
                model=task.expected_model,
                effort=task.expected_effort,
                secret_names=secret_names,
            )
        if not task.allow_model_override:
            raise WorkerError("the dedicated ACP profile model/effort does not exactly match")
        if not model_matches:
            mcp_refs = profile.get("mcp_server_refs")
            if mcp_refs not in (None, []):
                raise WorkerError("per-run model override cannot preserve profile MCP references")
        if secret_names is not None and any(name not in task.secrets for name in secret_names):
            raise WorkerError("per-run model override is missing profile secret references")

        effective_secrets = (
            {name: value for name, value in task.secrets.items() if name in set(secret_names)}
            if secret_names is not None
            else dict(task.secrets)
        )
        settings = _agent_settings_from_profile(profile, task.expected_model, task.expected_effort)
        _, discovery = await self._request(
            "POST",
            "/api/acp/models",
            body={"agent_settings": settings, "secrets": effective_secrets},
            timeout=30.0,
        )
        error = discovery.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            raise WorkerError(f"ACP model discovery failed ({code or 'unknown'})")
        available = discovery.get("available_models")
        if not isinstance(available, list):
            raise WorkerError("ACP model discovery returned no catalogue")
        model_ids = [
            item.get("model_id")
            for item in available
            if isinstance(item, dict) and isinstance(item.get("model_id"), str)
        ]
        if task.expected_model not in model_ids:
            raise WorkerError("the expected model is not offered by this ACP server")
        if task.expected_effort is not None and task.expected_effort not in _effort_values(
            discovery, task.expected_model
        ):
            raise WorkerError("the expected effort is not offered for this model")
        return ModelPreflight(
            profile_name=name,
            profile_id=task.profile_id,
            mode="profile" if model_matches else "override",
            acp_server=task.expected_acp_server,
            model=task.expected_model,
            effort=task.expected_effort,
            switch_model=not model_matches,
            switch_effort=(
                task.expected_effort is not None
                and (not model_matches or profile_effort != task.expected_effort)
            ),
            agent_settings=None if model_matches else settings,
            available_models=tuple(model_ids),
            secret_names=secret_names,
        )

    async def start(
        self,
        task: WorkerTask,
        *,
        branch_reader: BranchReader | None = None,
        model_verify_attempts: int = 20,
        model_verify_interval: float = 0.25,
    ) -> WorkerDispatch:
        """Create, verify and only then submit the task to the native worker."""
        if (
            not isinstance(model_verify_attempts, int)
            or isinstance(model_verify_attempts, bool)
            or not 1 <= model_verify_attempts <= 100
        ):
            raise WorkerError("model_verify_attempts must be between 1 and 100")
        if (
            not isinstance(model_verify_interval, int | float)
            or isinstance(model_verify_interval, bool)
            or not 0 <= model_verify_interval <= 2
        ):
            raise WorkerError("model_verify_interval must be between 0 and 2 seconds")
        repo_path = self._repo_path(task.repository)
        preflight = await self.preflight(task)
        body = build_start_request(task, repo_path, preflight)
        try:
            # Same-ID creates are serialized client-side. Upstream's lifecycle
            # lock is taken after worktree creation, so two concurrent creates
            # can race the force-remove step. This lock also serializes task
            # submission and run retries with stop() for the same id.
            async with self._start_lock(task.conversation_id):
                create: asyncio.Task[tuple[int, dict[str, Any]]] | None = None
                try:
                    async with self._start_slots:
                        create = asyncio.create_task(
                            self._request(
                                "POST",
                                "/api/conversations",
                                body=body,
                                timeout=task.timeout_seconds,
                            )
                        )
                        status, info = await asyncio.shield(create)
                except WorkerResponseError as exc:
                    if exc.status_code == 201:
                        await self._safe_interrupt(task.conversation_id)
                    raise
                except asyncio.CancelledError:
                    # The create POST was already admitted. Let it settle so a
                    # worker this call created can be interrupted; a reused
                    # conversation (HTTP 200) is left untouched. Cancellation
                    # before admission leaves the id unused.
                    settled, _ = await self._settle_create(create)
                    if settled == 201:
                        await self._safe_interrupt_shielded(task.conversation_id)
                    raise
                if status not in (200, 201):
                    raise WorkerError(f"unexpected OpenHands start status {status}")

                if status == 200:
                    # An existing conversation is never sent a second task.
                    legacy = self._validate_common(task, info, repo_path=repo_path)
                    if legacy:
                        raise WorkerError("a legacy conversation cannot be reused for dispatch")
                    dispatch = self._dispatch(task, info, created=False)
                    branch_verified = False
                    if branch_reader is not None:
                        await self._verify_branch(branch_reader, dispatch.workspace, task.branch)
                        branch_verified = True
                        dispatch = replace(dispatch, branch_verified=True)
                    submitted = False
                    try:
                        accepted = await self._task_accepted(task.conversation_id)
                        if accepted is False:
                            if dispatch.raw_status != "idle":
                                raise WorkerError("conversation exists without an accepted task")
                            await self._select_model_effort(task, preflight)
                            submitted = True
                            await self._submit_task(task)
                            info = await self._await_effective(
                                task,
                                attempts=model_verify_attempts,
                                interval=model_verify_interval,
                            )
                            self._validate_common(task, info, repo_path=repo_path)
                            dispatch = replace(
                                self._dispatch(task, info, created=False),
                                branch_verified=branch_verified or None,
                            )
                        elif accepted is True and dispatch.raw_status == "idle":
                            # The task was saved but the run slot was not admitted.
                            await self._select_model_effort(task, preflight)
                            submitted = True
                            await self._run_with_retry(task)
                            info = await self._await_effective(
                                task,
                                attempts=model_verify_attempts,
                                interval=model_verify_interval,
                            )
                            self._validate_common(task, info, repo_path=repo_path)
                            dispatch = replace(
                                self._dispatch(task, info, created=False),
                                branch_verified=branch_verified or None,
                            )
                        elif accepted is None and dispatch.raw_status == "idle":
                            raise WorkerError("the saved task state is unknown")
                    except asyncio.CancelledError:
                        if submitted:
                            # This call admitted the run; do not leave it
                            # running after the caller has gone away.
                            await self._safe_interrupt_shielded(task.conversation_id)
                        raise
                    if not dispatch.model_verified:
                        raise WorkerError(
                            "the existing conversation has no matching effective model"
                        )
                    if task.expected_effort is not None and not dispatch.effort_verified:
                        raise WorkerError(
                            "the existing conversation has no matching effective effort"
                        )
                    return dispatch

                try:
                    self._validate_common(task, info, repo_path=repo_path)
                    branch_verified = False
                    if branch_reader is not None:
                        await self._verify_branch(branch_reader, self._workspace(info), task.branch)
                        branch_verified = True
                    await self._select_model_effort(task, preflight)
                    await self._submit_task(task)
                    info = await self._await_effective(
                        task,
                        attempts=model_verify_attempts,
                        interval=model_verify_interval,
                    )
                    self._validate_common(task, info, repo_path=repo_path)
                    dispatch = self._dispatch(task, info, created=True)
                    if branch_verified:
                        dispatch = replace(dispatch, branch_verified=True)
                    return dispatch
                except asyncio.CancelledError:
                    # This request received HTTP 201, so it owns the worker.
                    await self._safe_interrupt_shielded(task.conversation_id)
                    raise
                except WorkerRunPending:
                    # The message is saved; a later retry can admit /run
                    # without reposting it.
                    raise
                except WorkerError:
                    await self._safe_interrupt(task.conversation_id)
                    raise
        except _HTTPTimeout:
            # Ownership is ambiguous after a lost create response. Return the
            # id for inspection rather than interrupting a possibly reused
            # conversation.
            raise WorkerTimeout(
                "OpenHands start timed out; query the conversation before retrying",
                task.conversation_id,
            ) from None
        except asyncio.CancelledError:
            raise

    async def status(
        self,
        task: WorkerTask,
        *,
        verify_pr: bool = False,
        branch_reader: BranchReader | None = None,
    ) -> WorkerStatus:
        """Read native status and, when terminal, validate the PR evidence."""
        repo_path = self._repo_path(task.repository)
        _, info = await self._request(
            "GET", f"/api/conversations/{task.conversation_id}", timeout=20.0
        )
        self._validate_common(task, info, repo_path=repo_path)
        raw_value = info.get("execution_status")
        raw_status = raw_value if isinstance(raw_value, str) else "unknown"
        state = map_status(raw_status)
        terminal = raw_status in _TERMINAL

        effective_model = self._effective_model(info)
        model_verified = effective_model == task.expected_model
        model_error = None
        if not model_verified:
            model_error = (
                "effective model not reported"
                if effective_model is None
                else "effective model does not match"
            )
        effective_effort = self._effective_effort(info)
        effort_verified: bool | None = None
        effort_error: str | None = None
        if task.expected_effort is not None:
            effort_verified = effective_effort == task.expected_effort
            if not effort_verified:
                effort_error = (
                    "effective effort not reported"
                    if effective_effort is None
                    else "effective effort does not match"
                )

        evidence: PullRequestEvidence | None = None
        evidence_error: str | None = None
        pr_verification: dict[str, Any] | None = None
        if terminal:
            try:
                _, final = await self._request(
                    "GET",
                    f"/api/conversations/{task.conversation_id}/agent_final_response",
                    timeout=20.0,
                )
                response = final.get("response")
                if not isinstance(response, str):
                    evidence_error = "OpenHands returned no worker final response"
                else:
                    evidence = parse_pr_evidence(response, task)
            except WorkerError as exc:
                evidence_error = str(exc)
        if verify_pr and evidence is not None and evidence.pr_url is not None:
            try:
                pr_verification = await self._verify_pr(evidence)
            except WorkerError as exc:
                pr_verification = {"verified": False, "error": str(exc)}

        workspace = self._workspace(info)
        actual_branch: str | None = None
        branch_verified: bool | None = None
        branch_error: str | None = None
        if branch_reader is not None:
            actual_branch, branch_error = await self._read_branch(branch_reader, workspace)
            if branch_error is None and actual_branch != task.branch:
                branch_error = "actual worktree branch does not match"
            branch_verified = branch_error is None

        return WorkerStatus(
            repository=task.repository_key,
            conversation_id=task.conversation_id,
            branch=task.branch,
            workspace=workspace,
            model=self._model(info),
            effective_model=effective_model,
            effort=task.expected_effort,
            effective_effort=effective_effort,
            acp_server=self._acp_server(info),
            raw_status=raw_status,
            state=state,
            terminal=terminal,
            pr=evidence,
            pr_verification=pr_verification,
            evidence_error=evidence_error,
            branch_verified=branch_verified,
            actual_branch=actual_branch,
            branch_error=branch_error,
            model_verified=model_verified,
            model_error=model_error,
            effort_verified=effort_verified,
            effort_error=effort_error,
        )

    async def list_repository(
        self,
        repository: str,
        *,
        limit: int = 100,
        max_pages: int = 20,
        max_results: int = 500,
        status: str | None = None,
    ) -> ScopedConversationList:
        """List only conversations carrying this repository's native tag.

        Live search has no repository filter, so results are filtered here.
        Missing/foreign scope is excluded; pre-tag conversations are not
        inferred and are only included through ``legacy_repository_by_id``.
        """
        key = _canonical_repo(repository)
        if key not in self._repositories:
            raise WorkerError("repository is not approved for worker dispatch")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise WorkerError("limit must be between 1 and 100")
        if (
            not isinstance(max_pages, int)
            or isinstance(max_pages, bool)
            or not 1 <= max_pages <= _MAX_SEARCH_PAGES
        ):
            raise WorkerError(f"max_pages must be between 1 and {_MAX_SEARCH_PAGES}")
        if (
            not isinstance(max_results, int)
            or isinstance(max_results, bool)
            or not 1 <= max_results <= _MAX_SEARCH_RESULTS
        ):
            raise WorkerError(f"max_results must be between 1 and {_MAX_SEARCH_RESULTS}")
        if status is not None and status not in _STATUS_MAP:
            raise WorkerError("status filter is not a known execution status")

        items: list[ScopedConversation] = []
        unclassified = 0
        seen: set[UUID] = set()
        page_id: str | None = None
        pages = 0
        while True:
            parameters = {"limit": str(limit)}
            if page_id is not None:
                parameters["page_id"] = page_id
            if status is not None:
                parameters["status"] = status
            _, page = await self._request(
                "GET",
                f"/api/conversations/search?{urlencode(parameters)}",
                timeout=20.0,
            )
            page_items = page.get("items")
            if not isinstance(page_items, list):
                raise WorkerError("OpenHands returned an invalid conversation page")
            pages += 1
            for info in page_items:
                if not isinstance(info, dict):
                    raise WorkerError("OpenHands returned an invalid conversation")
                conversation_id = _parse_uuid(info.get("id"))
                if conversation_id is None:
                    raise WorkerError("OpenHands returned an invalid conversation id")
                if conversation_id in seen:
                    continue
                seen.add(conversation_id)
                scope, legacy = self._scope_of(info)
                if scope is None:
                    unclassified += 1
                    continue
                if scope != key:
                    continue
                if len(items) >= max_results:
                    raise WorkerError("conversation list exceeds the result bound")
                raw_value = info.get("execution_status")
                raw = raw_value if isinstance(raw_value, str) else "unknown"
                title = info.get("title")
                items.append(
                    ScopedConversation(
                        repository=key,
                        conversation_id=conversation_id,
                        raw_status=raw,
                        state=map_status(raw),
                        title=(
                            redact_text(title[:200]) if isinstance(title, str) and title else None
                        ),
                        model=self._optional_model(info),
                        workspace=self._optional_workspace(info),
                        legacy=legacy,
                    )
                )
            next_page_id = page.get("next_page_id")
            if not next_page_id:
                break
            if pages >= max_pages:
                raise WorkerError("conversation list exceeds the page bound")
            if not isinstance(next_page_id, str) or next_page_id == page_id:
                raise WorkerError("OpenHands returned an invalid pagination token")
            if not page_items:
                raise WorkerError("OpenHands returned an empty page with a next token")
            page_id = next_page_id
        return ScopedConversationList(
            repository=key,
            items=tuple(items),
            unclassified_count=unclassified,
            pages=pages,
        )

    async def stop(self, task: WorkerTask, *, timeout: float = 20.0) -> WorkerStop:
        """Interrupt a scoped conversation and report its actual state."""
        try:
            async with asyncio.timeout(timeout):
                async with self._start_lock(task.conversation_id):
                    _, info = await self._request(
                        "GET",
                        f"/api/conversations/{task.conversation_id}",
                        timeout=20.0,
                    )
                    self._validate_scope(task, info)
                    await self._interrupt_raw(task.conversation_id, timeout=timeout)
                    try:
                        _, current = await self._request(
                            "GET",
                            f"/api/conversations/{task.conversation_id}",
                            timeout=20.0,
                        )
                        raw = current.get("execution_status")
                        raw_status = raw if isinstance(raw, str) else "unknown"
                    except WorkerError:
                        raw_status = "unknown"
        except TimeoutError:
            raise WorkerError("stop timed out waiting for the conversation") from None
        return WorkerStop(
            conversation_id=task.conversation_id,
            acknowledged=True,
            raw_status=raw_status,
            state=map_status(raw_status),
        )

    async def _interrupt_raw(self, conversation_id: UUID, *, timeout: float = 20.0) -> None:
        status, _ = await self._request(
            "POST", f"/api/conversations/{conversation_id}/interrupt", timeout=timeout
        )
        if status != 200:
            raise WorkerError(f"unexpected OpenHands stop status {status}")

    async def _safe_interrupt(self, conversation_id: UUID) -> None:
        try:
            await self._interrupt_raw(conversation_id)
        except WorkerError:
            pass

    async def _safe_interrupt_shielded(self, conversation_id: UUID) -> None:
        """Interrupt while suppressing repeated cancellation until it settles.

        Callers re-raise the original cancellation; keeping the cleanup task
        inside the per-id lock prevents a retry from reusing the id before the
        interrupt reaches Canvas.
        """
        interrupt = asyncio.create_task(self._safe_interrupt(conversation_id))
        try:
            while not interrupt.done():
                try:
                    await asyncio.shield(interrupt)
                except asyncio.CancelledError:
                    current = asyncio.current_task()
                    if current is not None and hasattr(current, "uncancel"):
                        current.uncancel()
                    continue
                except Exception:
                    break
        finally:
            if not interrupt.done():
                interrupt.cancel()

    async def _settle_create(
        self, create: asyncio.Task[tuple[int, dict[str, Any]]] | None
    ) -> tuple[int | None, dict[str, Any] | None]:
        """Await an admitted create after caller cancellation.

        The caller is already being cancelled; this only establishes whether
        the request created a worker (HTTP 201) so it can be interrupted. A
        second cancellation is suppressed until the admitted POST settles so
        the id cannot be reused while its outcome is unknown.
        """
        if create is None:
            return None, None
        try:
            while not create.done():
                try:
                    await asyncio.shield(create)
                except asyncio.CancelledError:
                    current = asyncio.current_task()
                    if current is not None and hasattr(current, "uncancel"):
                        current.uncancel()
                    continue
            return create.result()
        except WorkerResponseError as exc:
            return exc.status_code, None
        except (asyncio.CancelledError, Exception):
            return None, None

    async def _select_model_effort(self, task: WorkerTask, preflight: ModelPreflight) -> None:
        if preflight.switch_model:
            await self._request(
                "POST",
                f"/api/conversations/{task.conversation_id}/switch_acp_model",
                body={"model": task.expected_model},
                timeout=30.0,
            )
        if preflight.switch_effort:
            await self._request(
                "POST",
                f"/api/conversations/{task.conversation_id}/switch_acp_effort",
                body={"effort": task.expected_effort},
                timeout=30.0,
            )

    async def _submit_task(self, task: WorkerTask) -> None:
        try:
            await self._request(
                "POST",
                f"/api/conversations/{task.conversation_id}/events",
                body=build_task_message(task),
                timeout=30.0,
            )
            return
        except WorkerHTTPError as exc:
            # 429 means the message was saved but no run slot was available.
            if exc.status_code != 429:
                raise
        await self._run_with_retry(task)

    async def _run_with_retry(self, task: WorkerTask) -> None:
        for attempt in range(3):
            try:
                await self._request(
                    "POST",
                    f"/api/conversations/{task.conversation_id}/run",
                    timeout=30.0,
                )
                return
            except WorkerHTTPError as exc:
                if exc.status_code == 409:
                    # A previous /run may have been admitted without its
                    # response reaching us; Canvas can still report idle while
                    # ACP initializes. Poll briefly, then keep the saved task
                    # pending rather than reporting a false failure.
                    if await self._await_active(task.conversation_id):
                        return
                    if attempt == 2:
                        raise WorkerRunPending(task.conversation_id) from None
                    await asyncio.sleep(0.25 * (attempt + 1))
                    continue
                if exc.status_code != 429:
                    raise
                if attempt == 2:
                    raise WorkerRunPending(task.conversation_id) from None
                await asyncio.sleep(0.25 * (attempt + 1))

    async def _await_active(
        self, conversation_id: UUID, *, attempts: int = 5, interval: float = 0.15
    ) -> bool:
        for attempt in range(attempts):
            if await self._is_active(conversation_id):
                return True
            if attempt + 1 < attempts:
                await asyncio.sleep(interval)
        return False

    async def _is_active(self, conversation_id: UUID) -> bool:
        try:
            _, info = await self._request(
                "GET", f"/api/conversations/{conversation_id}", timeout=20.0
            )
        except WorkerError:
            return False
        raw = info.get("execution_status")
        return raw in {"running", "waiting_for_confirmation"}

    async def _task_accepted(self, conversation_id: UUID) -> bool | None:
        try:
            _, page = await self._request(
                "GET",
                f"/api/conversations/{conversation_id}/events/search"
                "?limit=1&kind=MessageEvent&source=user",
                timeout=20.0,
            )
        except WorkerError:
            return None
        items = page.get("items")
        if not isinstance(items, list):
            return None
        return bool(items)

    async def _await_effective(
        self, task: WorkerTask, *, attempts: int, interval: float
    ) -> dict[str, Any]:
        for attempt in range(attempts):
            _, info = await self._request(
                "GET", f"/api/conversations/{task.conversation_id}", timeout=20.0
            )
            raw_status = info.get("execution_status")
            effective_model = self._effective_model(info)
            effective_effort = self._effective_effort(info)
            if (
                isinstance(raw_status, str)
                and raw_status != "idle"
                and effective_model == task.expected_model
                and (task.expected_effort is None or effective_effort == task.expected_effort)
            ):
                return info
            if effective_model is not None and effective_model != task.expected_model:
                raise WorkerError("effective model does not match")
            if (
                task.expected_effort is not None
                and effective_effort is not None
                and effective_effort != task.expected_effort
            ):
                raise WorkerError("effective effort does not match")
            if attempt + 1 < attempts and interval:
                await asyncio.sleep(interval)
        raise WorkerError("effective model/effort was not reported before the task")

    async def _read_branch(
        self, reader: BranchReader, workspace: str
    ) -> tuple[str | None, str | None]:
        try:
            async with asyncio.timeout(5.0):
                actual = await reader(workspace)
        except TimeoutError:
            return None, "branch read timed out"
        except Exception as exc:
            return None, f"branch read failed ({type(exc).__name__})"
        if not isinstance(actual, str) or not actual:
            return None, "branch reader returned no branch"
        return actual, None

    async def _verify_branch(self, reader: BranchReader, workspace: str, branch: str) -> None:
        actual, error = await self._read_branch(reader, workspace)
        if error or actual != branch:
            raise WorkerError(error or "actual worktree branch does not match")

    def _validate_scope(self, task: WorkerTask, info: dict[str, Any]) -> bool:
        """Validate id and repository scope; model changes do not block cancel."""
        if info.get("id") != str(task.conversation_id):
            raise WorkerError("OpenHands returned a different conversation id")
        scope, legacy = self._scope_of(info)
        if scope is None:
            raise WorkerError("conversation has no approved repository scope")
        if scope != task.repository_key:
            raise WorkerError("conversation belongs to a different repository")
        if not legacy:
            tags = info.get("tags")
            if not isinstance(tags, dict) or any(
                tags.get(key) != task.tags[key] for key in (REPOSITORY_TAG, "kuleissue", "kuletask")
            ):
                raise WorkerError("conversation id is already used by a different task")
        return legacy

    def _validate_common(self, task: WorkerTask, info: dict[str, Any], *, repo_path: str) -> bool:
        """Validate id, repository scope, configured identity and worktree."""
        if info.get("id") != str(task.conversation_id):
            raise WorkerError("OpenHands returned a different conversation id")
        scope, legacy = self._scope_of(info)
        if scope is None:
            raise WorkerError("conversation has no approved repository scope")
        if scope != task.repository_key:
            raise WorkerError("conversation belongs to a different repository")
        if not legacy:
            tags = info.get("tags")
            if not isinstance(tags, dict) or any(
                tags.get(key) != value for key, value in task.tags.items()
            ):
                raise WorkerError("conversation id is already used by a different task")
        if self._model(info) != task.expected_model:
            raise WorkerError("configured conversation model does not exactly match")
        if self._acp_server(info) != task.expected_acp_server:
            raise WorkerError("conversation ACP server does not exactly match")

        workspace = self._workspace(info)
        workspace_path = Path(workspace).resolve()
        repo_root = Path(repo_path).resolve()
        if legacy:
            if workspace_path != repo_root and not workspace_path.is_relative_to(repo_root):
                if str(task.conversation_id) not in Path(workspace).parts:
                    raise WorkerError("legacy conversation is outside its repository")
        else:
            if str(task.conversation_id) not in Path(workspace).parts:
                raise WorkerError("conversation is not in its native worktree")
            if workspace_path == repo_root:
                raise WorkerError("native worktree was not created")
        return legacy

    def _dispatch(self, task: WorkerTask, info: dict[str, Any], *, created: bool) -> WorkerDispatch:
        raw_value = info.get("execution_status")
        raw_status = raw_value if isinstance(raw_value, str) else "unknown"
        effective_model = self._effective_model(info)
        effective_effort = self._effective_effort(info)
        return WorkerDispatch(
            repository=task.repository_key,
            conversation_id=task.conversation_id,
            branch=task.branch,
            workspace=self._workspace(info),
            model=self._model(info),
            effective_model=effective_model,
            effort=task.expected_effort,
            effective_effort=effective_effort,
            acp_server=self._acp_server(info),
            created=created,
            raw_status=raw_status,
            state=map_status(raw_status),
            model_verified=effective_model == task.expected_model,
            effort_verified=(
                None if task.expected_effort is None else effective_effort == task.expected_effort
            ),
        )

    @staticmethod
    def _with_branch_verified(dispatch: WorkerDispatch) -> WorkerDispatch:
        return replace(dispatch, branch_verified=True)

    @staticmethod
    def _workspace(info: dict[str, Any]) -> str:
        workspace = info.get("workspace")
        if not isinstance(workspace, dict) or workspace.get("kind") != "LocalWorkspace":
            raise WorkerError("OpenHands returned an invalid workspace")
        working_dir = workspace.get("working_dir")
        if not isinstance(working_dir, str) or not Path(working_dir).is_absolute():
            raise WorkerError("OpenHands returned an invalid workspace path")
        return working_dir

    @classmethod
    def _optional_workspace(cls, info: Mapping[str, Any]) -> str | None:
        try:
            return cls._workspace(info)
        except WorkerError:
            return None

    @staticmethod
    def _model(info: Mapping[str, Any]) -> str:
        agent = info.get("agent")
        if not isinstance(agent, dict) or agent.get("kind") != "ACPAgent":
            raise WorkerError("the conversation agent is not ACP")
        model = agent.get("acp_model")
        if not isinstance(model, str) or not model:
            raise WorkerError("the conversation has no exact ACP model")
        return model

    @classmethod
    def _optional_model(cls, info: Mapping[str, Any]) -> str | None:
        try:
            return cls._model(info)
        except WorkerError:
            return None

    @staticmethod
    def _effective_model(info: Mapping[str, Any]) -> str | None:
        model = info.get("current_model_id")
        return model if isinstance(model, str) and model else None

    @staticmethod
    def _effective_effort(info: Mapping[str, Any]) -> str | None:
        effort = info.get("current_effort")
        return effort if isinstance(effort, str) and effort else None

    @staticmethod
    def _acp_server(info: Mapping[str, Any]) -> str:
        agent = info.get("agent")
        if not isinstance(agent, dict):
            raise WorkerError("the conversation has no agent")
        server = agent.get("acp_server")
        if not isinstance(server, str) or not server:
            raise WorkerError("the conversation has no exact ACP server")
        return server

    async def _verify_pr(self, evidence: PullRequestEvidence) -> dict[str, Any]:
        if evidence.pr_url is None:
            raise WorkerError("blocker-only evidence has no pull request")
        match = _PR_RE.fullmatch(evidence.pr_url)
        if not match:
            raise WorkerError("pr_url is invalid")
        owner, repo, number = match.groups()
        try:
            _canonical_repo(f"{owner}/{repo}")
        except WorkerError:
            raise WorkerError("pr_url is not a valid repository URL") from None
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
        branch_verified: bool | None = None
        head_ref = pr.get("head_ref")
        if isinstance(head_ref, str) and head_ref:
            if head_ref != evidence.branch:
                raise WorkerError("the pull request branch does not match the reported branch")
            branch_verified = True
        checks = pr.get("checks")
        state = pr.get("state")
        if not isinstance(checks, str) or not isinstance(state, str):
            raise WorkerError("OpenHands returned an invalid pull request status")
        return {
            "verified": True,
            "branch_verified": branch_verified,
            "state": state,
            "checks": checks,
            "draft": bool(pr.get("draft")),
            "head_sha": pr["head_sha"],
        }
