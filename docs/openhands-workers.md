# WS-OH-WORKERS (kule#23 LEG 2) — source-only OpenHands worker workflow

**Status: source-only; no live worker was dispatched and no production change is implied.** The module is not registered as a Kule MCP tool. LEG 1 owns the general Canvas session API in #27; this module is the worker-specific specialization and does not duplicate that public lifecycle.

## Relationship to #27

#27 is the public, repository-scoped Canvas adapter: it owns the MCP tools, operation allowlist, OAuth/audit boundary and general conversation lifecycle. This module owns only the worker-specific parts: task brief, native worktree identity, exact model/effort selection, start/status mapping, PR/blocker evidence and branch checks. It adds no MCP tool, route, queue or second conversation store. When #27 lands, its repository-scoped session operations can back this helper; do not expose a second public list/get/start surface from this module.

## What this adds

`src/operator_mcp/worker_workflow.py` creates a native OpenHands conversation in two phases: first without the task, then after the worktree/model/effort have been verified, it submits the task. It does not add a runtime, queue, conversation database, scheduler or worktree manager.

- Resolves the repository path from an approved `owner/repo -> absolute path` mapping. Callers cannot supply an arbitrary server path.
- Requires the task's issue `owner/repo` to match `repository`, and writes the canonical native tag `kulerepo=owner/repo` (lowercase).
- Scopes list, status, cancel and dispatch to that repository. Direct operations fail closed when the native tag is missing, foreign or ambiguous.
- Generates one native `conversation_id` and binds issue, task digest, model, profile, branch and effort into native tags.
- Requests the native `worktree: true` lifecycle. The server creates `/tmp/conversation-worktrees/<conversation_id>/<repo>` and branch `<prefix><conversation_id>`.
- Creates the conversation with **no** `initial_message`, verifies the native worktree and configured identity, selects the exact ACP model/effort through the native switch endpoints, then sends the task with `run: true`.
- Verifies the effective `current_model_id` and optional `current_effort` before returning a successful dispatch. It fails closed and interrupts the newly created worker if they are missing or different.
- Maps native execution states to a small worker vocabulary, parses structured PR or blocker-only evidence, and optionally verifies the PR URL/head/CI.
- Admits a bounded number of start requests at a time with an in-process semaphore and serializes same-id create attempts. This is request admission, **not** active-worker concurrency and not a durable queue.
- Interrupts a newly created conversation when post-create verification fails. A reused conversation is never interrupted by a collision.
- Does **not** delete conversations or worktrees. Upstream deletion force-removes the worktree, so dirty/unpushed cleanup remains an explicit operator decision.

## Verified upstream contract

Verified from upstream source, not from a live worker:

- Repository: `OpenHands/software-agent-sdk`
- Tag: `v1.62.0`
- Commit: `504a88cab0fb48ee5226238ad7b8f1d865fa84a8`
- Request: `openhands-sdk/openhands/sdk/conversation/request.py`
- Routes: `openhands-agent-server/openhands/agent_server/conversation_router.py`
- ACP discovery: `openhands-agent-server/openhands/agent_server/acp_router.py`
- PR status: `openhands-agent-server/openhands/agent_server/git_router.py`

Fields/routes used by this module:

| Purpose | Upstream contract |
| --- | --- |
| Create conversation | `POST /api/conversations`, no `initial_message` |
| Native worktree | `worktree: bool`, `worktree_options.base`, `worktree_options.branch_prefix` |
| Dedicated profile | `agent_profile_id` |
| Per-run model | `agent_settings` (`ACPAgentSettings`) |
| Submit task | `POST /api/conversations/{id}/events` with `run: true` |
| Retry saved task | `POST /api/conversations/{id}/run` after a 429 |
| Native model/effort | `POST /api/conversations/{id}/switch_acp_model`, `.../switch_acp_effort` |
| Bounded run | `max_iterations`, `max_budget_per_run` |
| Native identity | `tags`, including `kulerepo` |
| Search | `GET /api/conversations/search?limit=...&page_id=...` |
| Status | `GET /api/conversations/{id}` (`execution_status`, `current_model_id`, `current_effort`) |
| Final evidence | `GET /api/conversations/{id}/agent_final_response` |
| Cancel | `POST /api/conversations/{id}/interrupt` |
| Profile check | `GET /api/agent-profiles`, `GET /api/agent-profiles/{name}` |
| Model catalogue | `POST /api/acp/models` |
| PR check | `GET /api/git/repositories/{owner}/{repo}/pull-requests/{number}?provider=github` |

Native statuses used: `idle`, `running`, `paused`, `waiting_for_confirmation`, `finished`, `error`, `stuck`, `deleting`. The worker states are `pending`, `running`, `paused`, `needs_attention`, `completed`, `failed`, `stuck`, `deleting`, or `unknown`.

The live Canvas `/openapi.json` was not read from this source-only environment. The live deployment's SDK version and profile IDs must still be checked before the first dispatch. The pinned source is the contract this code tests against.

## Repository scope

Live `GET /api/conversations/search` is paginated but has **no repository filter**. This module therefore:

1. pages through native search with a hard page bound and result bound;
2. accepts only conversations whose `tags.kulerepo` exactly matches an approved repository;
3. counts conversations with no usable tag as `unclassified_count` and does not return their details;
4. never infers a repository from a title, path or workspace.

The client requires an approved mapping:

```python
repositories = {
    "yesvus/kule": "/workspace/src/kule",
}
```

The task's issue reference must use the same `owner/repo`. The canonical tag is `kulerepo=owner/repo` (lowercase, matching GitHub's case-insensitive identity). Direct status, cancel and dispatch fail closed if the conversation has no approved scope or belongs to a different repository.

### Pre-tag and unknown conversations

Existing conversations created before the tag was introduced are **not** auto-classified. An operator may provide an explicit, bounded mapping for known ids:

```python
legacy_repository_by_id = {
    UUID("..."): "yesvus/kule",
}
```

Only those exact ids are treated as legacy-scoped. A missing tag is otherwise an error for status/cancel and is counted as unclassified in list results. A legacy conversation can be read or cancelled with explicit scope, but it is never reused for a new dispatch.

## Exact model and effort

The issue requested `opencode-go/deepseek-v4.1-flash-1017`. OpenCode's selectable model ID is:

```text
opencode-go/deepseek-v4.1-flash
```

`DeepSeek V4.1 Flash 1017` is the model's display name, not an ID. The module defaults to the selectable ID and never substitutes a different or more expensive model.

The live global `opencode` profile may have a different default. Dispatch supports two verified modes:

- **Dedicated profile:** if the stored profile's `acp_model` (and optional `acp_effort`) already matches, the create request uses `agent_profile_id` unchanged.
- **Per-run override:** otherwise the module derives an `ACPAgentSettings` payload from the existing profile with the requested model/effort, calls `POST /api/acp/models`, requires the exact model in `available_models` and the exact effort in `efforts_by_model`, then creates with `agent_settings`. The stored profile is not mutated. The native `switch_acp_model`/`switch_acp_effort` endpoints are called before the task is submitted.

Override fails closed when it cannot preserve non-empty profile MCP references or when required profile secret references are absent. A `null`/all-MCP profile is not resolved by this source-only override either; use a dedicated profile if the worker needs MCP servers. `secrets` is an opaque OpenHands `SecretSource` mapping supplied by the trusted adapter. It is filtered by the profile's `secret_refs`: an explicit list allows only those names, an empty list forwards none, and a missing/`null` value forwards every task-supplied secret. Secrets are never logged or included in status output. Set `allow_model_override=False` to require a dedicated, explicitly configured profile.

The configured model is not treated as proof of the running model. `WorkerDispatch.model_verified` is only true after the effective `current_model_id` matches. `status()` reports `model_verified`, `effective_model` and `model_error`, plus the equivalent effort fields. If the effective model/effort is not reported after the task is submitted, `start()` interrupts the worker and fails rather than returning a configured-only success.

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
    task="Implement only the assigned LEG 2 scope.",
    profile_id=PROFILE_UUID,
    branch_prefix="oh23/ws-oh-workers/",
    max_budget_per_run=2.0,
)

async with WorkerClient(
    os.environ[API_URL_ENV],
    api_key_from_env(),
    repositories={"yesvus/kule": "/workspace/src/kule"},
) as client:
    dispatch = await client.start(task)
    status = await client.status(task, verify_pr=True)
    print(dispatch.as_dict())
    print(status.as_dict())
```

`conversation_id` is generated before the POST. The native tags (`kulerepo`, `kuleissue`, `kuletask`, `kulemodel`, `kuleprofile`, `kulebranch`, `kuleeffort`) bind the reuse identity. Passing an identical task/id on retry returns the existing conversation with HTTP 200 and **does not send the task again**. A different branch, effort, model, profile or issue is rejected without interrupting the existing conversation.

Do not derive ids deterministically from the task text. If an old conversation with the same id was deleted, the upstream planner may force-remove a stale worktree with that id. Same-id starts are serialized in this client, but upstream create is not atomic across independent clients; do not dispatch the same id from separate processes.

## Evidence, branch and PR

The worker's final message must contain a fenced block. The parser uses the **last** matching block; it does not require the block to be the final text, so trailing prose is ignored.

Successful PR report:

````text
```worker-evidence
{"pr_url": "https://github.com/OWNER/REPO/pull/N", "branch": "...", "commit": "<40 lowercase hex>", "tests": ["command: result"], "blockers": []}
```
````

Blocked, no PR:

````text
```worker-evidence
{"blockers": ["specific reason and next owner action"]}
```
````

A PR report is rejected if the URL is outside the task repository, the branch differs, the commit is not 40 lowercase hex, or tests are empty. Free-form test and blocker lines pass through the existing best-effort secret redaction and length limits. Field-level violations are returned as `evidence_error`. The initial status GET remains a hard failure; a failed final-response GET or oversized/invalid final body is returned as `evidence_error` with the known terminal state.

`verify_pr=True` asks the OpenHands server to read the PR and combined CI with its own provider credential. It requires the PR URL and head SHA to match the evidence. If the live response also provides an authoritative `head_ref`, it must match the reported branch and `branch_verified` becomes true; otherwise `branch_verified` is `null` and the branch remains unverified. A matching URL/commit alone is not branch verification. A missing provider token is reported as an unverified PR, not as success.

The pinned conversation API has no checked-out branch field. A live adapter should pass a read-only `branch_reader(workspace) -> branch`; status then reports `branch_verified`, `actual_branch` and `branch_error`, and start checks the branch before submitting the task. Without a reader, `branch_verified` is `None`, which is explicitly not a verification.

## List

```python
result = await client.list_repository("yesvus/kule", max_pages=20, max_results=500)
print(result.as_dict())
```

The result is bounded and repository-scoped. `unclassified_count` says how many searched conversations had no usable `kulerepo` tag; their ids and details are not returned. The default page size is 100, the maximum page bound is 100 and the maximum result bound is 1000. Exceeding a bound fails closed rather than returning a partial silent list.

## Start admission, timeout, reconciliation and cancel

- **Start admission:** `WorkerClient(max_concurrent_starts=2)` admits at most two start POSTs at once. This is request admission only. It does not count running workers, bound total active conversations or provide a queue.
- **Same id:** a per-conversation client lock serializes create attempts for one id while different ids proceed in parallel.
- **Timeout:** the create POST uses `timeout_seconds`. A lost create response cannot prove whether this request created the worker, so `WorkerTimeout` returns the client-generated id for inspection and does **not** interrupt a possibly reused conversation.
- **Cancellation:** the caller's cancellation is preserved. Cancellation during the create POST is ambiguous and does not interrupt; cancellation after a known HTTP 201 interrupts the worker this request created.
- **201 body failure:** an invalid or oversized 201 body interrupts the newly created worker. An invalid/oversized 200 body never interrupts an existing conversation.
- **Retry after a saved task:** a 200 reuse is not treated as a completed dispatch. If the conversation is idle and has no user message, the task is submitted once; if the task is saved but the run was never admitted, only `/run` is retried. A running/finished conversation is a no-op.
- **429 on task submission:** the message is already saved; the client retries `POST /run` with bounded backoff instead of resending it.
- **Cancel:** `stop(task)` checks repository scope under the same per-id lock as start, calls native `/interrupt`, then reads the actual state. It does not report `paused` from the acknowledgment alone and never calls `DELETE`.

## Cleanup protection

This module intentionally has no delete/cleanup method. Upstream `DELETE /api/conversations/{id}` calls `remove_conversation_worktree`, which force-removes the conversation's worktree directory even when the branch was not pushed. Automating it would risk losing uncommitted or unpushed work.

Any future cleanup path must, at minimum, prove the PR/head commit is on the remote and that the worktree has no local changes before asking the native server to delete. Until that is implemented and reviewed, leave cleanup to an explicit operator action.

## Configuration and security

| Setting | Source |
| --- | --- |
| API origin | `KULE_OPENHANDS_API_URL` |
| Session key | `KULE_OPENHANDS_API_KEY` |
| Approved repositories | explicit `repositories` mapping |
| Explicit legacy ids | optional `legacy_repository_by_id` mapping |

The origin must be a bare HTTPS origin. Redirects and ambient HTTP(S) proxies are disabled, responses are streamed with a hard byte cap before JSON decoding, and error messages never include response bodies. The key must be a scoped service identity, not a browser session, broad operator token or SSH key. Do not enable live dispatch while the shared Tezgah HOME still exposes legacy GitHub/SSH operator credentials (ops#731).

This is a source capability. Enabling live workers still requires the LEG 3 trust-boundary acceptance, a real scoped developer GitHub identity, live profile/model discovery, capacity checks and an owner-reviewed rollout.

## Tests

```bash
python -m pytest -q tests/test_worker_workflow.py
```

The focused suite uses `httpx2.MockTransport`; it needs no OpenHands server, cluster, network or secret.
