# WS-OH-WORKERS (kule#23 LEG 2) — source-only OpenHands worker workflow

**Status: source-only; no live worker was dispatched and no production change is implied.** The module is not registered as a Kule MCP tool. LEG 1 owns the OpenHands MCP adapter; this leg owns the worker contract that adapter (or a trusted operator bridge) can call.

## What this adds

`src/operator_mcp/worker_workflow.py` is a small library around the OpenHands conversation API. It does not add a runtime, queue, conversation database, scheduler or worktree manager.

- Builds one `StartConversationRequest` per task with a client-generated `conversation_id`.
- Requests the native `worktree: true` lifecycle and the upstream `ConversationWorktreeOptions` branch prefix. The server creates `/tmp/conversation-worktrees/<conversation_id>/<repo>` and branch `<prefix><conversation_id>`.
- Checks the exact stored ACP profile and model before dispatch and again from the returned conversation.
- Maps native execution states to a small worker vocabulary.
- Parses the worker's final PR evidence and optionally verifies the PR head and combined CI through the server's read-only git endpoint.
- Bounds concurrent starts with an in-process semaphore. It is not a durable queue.
- Interrupts a conversation on cancel or when post-start validation fails.
- Does **not** delete conversations or worktrees. Upstream deletion force-removes the worktree, so dirty/unpushed cleanup must remain an explicit operator decision.

## Verified upstream contract

Verified from upstream source, not from a live worker:

- Repository: `OpenHands/software-agent-sdk`
- Tag: `v1.62.0`
- Commit: `504a88cab0fb48ee5226238ad7b8f1d865fa84a8`
- Request: `openhands-sdk/openhands/sdk/conversation/request.py`
- Routes: `openhands-agent-server/openhands/agent_server/conversation_router.py`
- PR status: `openhands-agent-server/openhands/agent_server/git_router.py`

Fields used by this module:

| Purpose | Upstream field |
| --- | --- |
| Start or reuse | `POST /api/conversations`, optional client `conversation_id` |
| Native worktree | `worktree: bool`, `worktree_options.base`, `worktree_options.branch_prefix` |
| ACP profile | `agent_profile_id` |
| First task | `initial_message` (`SendMessageRequest`) |
| Bounded run | `max_iterations`, `max_budget_per_run` |
| Runtime | `conversation_runtime` |
| Native labels | `tags` |
| Status | `GET /api/conversations/{id}` (`execution_status`) |
| Final evidence | `GET /api/conversations/{id}/agent_final_response` |
| Cancel | `POST /api/conversations/{id}/interrupt` |
| Profile check | `GET /api/agent-profiles`, `GET /api/agent-profiles/{name}` |
| PR check | `GET /api/git/repositories/{owner}/{repo}/pull-requests/{number}?provider=github` |

Native statuses used: `idle`, `running`, `paused`, `waiting_for_confirmation`, `finished`, `error`, `stuck`, `deleting`. The worker states are `pending`, `running`, `paused`, `needs_attention`, `completed`, `failed`, `stuck`, `deleting`, or `unknown`.

The live Canvas `/openapi.json` was not read from this source-only environment. The issue's 2026-11-18 preflight observed the same native worktree fields, but the deployed SDK version and profile IDs must still be checked before the first live dispatch. The pinned source is the contract this code tests against.

## Exact model

The issue requested `opencode-go/deepseek-v4.1-flash-1017`. OpenCode's selectable model ID is:

```text
opencode-go/deepseek-v4.1-flash
```

`DeepSeek V4.1 Flash 1017` is the model's display name, not an ID. The module therefore defaults to `opencode-go/deepseek-v4.1-flash` and never substitutes a different or more expensive model. This is a correction of the requested ID, not a silent substitution.

Dispatch fails closed unless all of these match exactly:

- the requested `expected_model` string;
- the stored ACP profile's `acp_model`;
- the returned conversation's agent `acp_model` and `acp_server`.

A profile with `acp_model: null` (server default) is not accepted for an ordinary worker because it cannot be validated in advance. Use a dedicated ACP profile whose model is pinned.

## One task, one branch, one worktree, one conversation

```python
import os
from operator_mcp.worker_workflow import (
    API_URL_ENV,
    WorkerClient,
    WorkerTask,
    api_key_from_env,
)

task = WorkerTask(
    issue_ref="yesvus/kule#23",
    repository="yesvus/kule",
    repo_path="/workspace/src/kule",
    task="Implement only the assigned LEG 2 scope.",
    profile_id=PROFILE_UUID,                 # exact ACP profile UUID
    branch_prefix="oh23/ws-oh-workers/",
    max_budget_per_run=2.0,
)

async with WorkerClient(os.environ[API_URL_ENV], api_key_from_env()) as client:
    dispatch = await client.start(task)
    print(dispatch.conversation_id, dispatch.branch)
```

`conversation_id` is generated before the POST. The upstream server creates the worktree and branch from it. Passing the same `conversation_id` on a retry returns the existing conversation with HTTP 200 instead of creating a second worktree. The module verifies native `tags` (`kuleissue`, `kuletask`, `kulemodel`, `kulerepopath`) so a reused id cannot silently point at different work. A collision on a 200 response is reported but does not interrupt the existing conversation.

Do not derive ids deterministically from the task text. If an old conversation with the same id was deleted, the upstream planner may force-remove a stale worktree with that id.

## Status and PR evidence

```python
status = await client.status(task, verify_pr=True)
print(status.as_dict())
```

The worker's final message must end with one fenced block:

````text
```worker-evidence
{"pr_url": "https://github.com/OWNER/REPO/pull/N", "branch": "...", "commit": "<40 lowercase hex>", "tests": ["command: result"], "blockers": []}
```
````

Evidence is rejected if the PR is outside the task repository, the branch differs, the commit is not 40 lowercase hex, tests are empty, or the text is oversized. Free-form test and blocker lines pass through the existing best-effort secret redaction and length limits. Invalid evidence is returned as `evidence_error`; it does not crash status.

`verify_pr=True` asks the OpenHands server to read the PR and combined CI using its own configured provider credential. It then requires the PR URL and head SHA to match the worker's evidence. `pr_verification` contains `verified`, `state`, `checks`, `draft` and `head_sha`. A missing provider token is reported as an unverified PR, not as a successful check. This module does not hold a GitHub token.

The branch reported in status is the branch the pinned upstream planner creates from `branch_prefix + conversation_id`. Upstream `ConversationInfo` has no branch field, so the module verifies the unique worktree path and model, not the checked-out branch via the API.

## Duplicate dispatch, concurrency, timeout and cancel

- **Duplicate:** same `conversation_id` + same tags/model/workspace returns the existing conversation (`created: false`). A mismatched tag aborts and interrupts.
- **Concurrency:** `WorkerClient(max_concurrent=2)` admits at most two start POSTs at once. There is no persistent queue and no second scheduling runtime.
- **Timeout:** the start POST uses `timeout_seconds`. If the response is lost, `WorkerTimeout` keeps the client-generated id so the caller can query before retrying.
- **Cancel:** `stop(conversation_id)` calls native `/interrupt`. It never calls `DELETE`.
- **Unsafe post-start state:** wrong model, wrong ACP server, missing worktree or an id collision triggers a best-effort interrupt.

## Cleanup protection

This module intentionally has no delete/cleanup method. Upstream `DELETE /api/conversations/{id}` calls `remove_conversation_worktree`, which force-removes the conversation's worktree directory even when the branch was not pushed. Automating it would risk losing uncommitted or unpushed work.

Any future cleanup path must, at minimum, prove the PR/head commit is on the remote and that the worktree has no local changes before asking the native server to delete. Until that is implemented and reviewed, leave cleanup to an explicit operator action.

## Configuration and security

| Setting | Source |
| --- | --- |
| API origin | `KULE_OPENHANDS_API_URL` |
| Session key | `KULE_OPENHANDS_API_KEY` |

The origin must be a bare HTTPS origin. Redirects are refused, responses are bounded, and error messages never include response bodies. The key must be a scoped service identity, not a browser session, broad operator token or SSH key. Do not enable live dispatch while the shared Tezgah HOME still exposes legacy GitHub/SSH operator credentials (ops#731).

This is a source capability. Enabling live workers still requires the LEG 3 trust-boundary acceptance, a real scoped developer GitHub identity, live profile/model discovery, capacity checks and an owner-reviewed rollout.

## Tests

```bash
python -m pytest -q tests/test_worker_workflow.py
```

The focused suite uses `httpx2.MockTransport`; it needs no OpenHands server, cluster, network or secret.
