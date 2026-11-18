# WS-OH-MCP (#23 leg 1) — OpenHands Agent Canvas management integration

**Status: source-only; OFF by default. No live Canvas call, credential, NetworkPolicy or
GitOps change is included.**

Kule remains the single authenticated MCP gateway. This adapter exposes a small,
explicitly allowlisted subset of the existing OpenHands Agent Canvas management API
to authenticated Kule callers. It does not start a second runtime, OAuth server,
orchestration queue or conversation database.

## Upstream-first decision

The pinned runtime is Agent Server `1.62.0`. Its OpenAPI contract is the maintained
management interface. The installed `openhands-sdk` ships MCP **client** support
(`openhands/sdk/mcp`), not a maintained MCP server for Agent Server management
routes, so there is no compatible upstream MCP server to mount. Kule therefore uses
FastMCP 4.2.0 `FastMCP.from_openapi()` and reduces the upstream schema before mount:

- `src/operator_mcp/openapi/openhands-1.62.0.json` is the pinned Canvas
  `GET /openapi.json` document, captured from the known Canvas port 8000 on
  2026-11-18. It is a fixture only; this PR does not call the live service.
  Replace it only with a reviewed schema for an explicitly pinned version.
- The adapter keeps only reviewed `operationId` entries, parameters and request
  properties. New upstream endpoints and fields stay invisible until reviewed.
- No endpoint-by-endpoint wrapper code is used.

## Transport and identity

| Setting | Requirement |
| --- | --- |
| `KULE_OPENHANDS_ENABLED` | Must be exactly `1`; default off. |
| `KULE_OPENHANDS_API_URL` | One fixed **HTTPS** origin, optional port, no path/query/userinfo. |
| `KULE_OPENHANDS_API_KEY` | Dedicated Canvas service key, sent only as `X-Session-API-Key`. Never a browser cookie or shared operator credential. |
| `KULE_OPENHANDS_WORKSPACE_ROOT` | Absolute POSIX root for launch targets; default `/workspace/src`. `/` is rejected. |

The HTTP client pins the origin, disables redirects and ignores proxy environment
variables, so the service key cannot follow a redirect or an ambient proxy to another
host. The key is never a tool argument and is not written to the audit log.

The native Canvas listener is currently plain HTTP on port 8000. This adapter rejects
`http://` because that would send the service key in cleartext. Enabling it in a Pod
requires a reviewed TLS ingress or local TLS terminator; that is a live-rollout gate,
not part of this source change.

## Endpoint allowlist

Every tool carries exactly one Kule tier. `read` and `operate` still require the
existing operator group; untagged tools fail closed.

| Tool | Upstream operation | Tier |
| --- | --- | --- |
| `oh_list_conversations` | `GET /api/conversations/search` | read |
| `oh_count_conversations` | `GET /api/conversations/count` | read |
| `oh_get_conversation` | `GET /api/conversations/{id}` | read |
| `oh_get_conversation_runtime` | `GET /api/conversations/{id}/runtime` | read |
| `oh_search_events` | `GET /api/conversations/{id}/events/search` | read |
| `oh_get_event` | `GET /api/conversations/{id}/events/{event_id}` | read |
| `oh_list_agent_profiles` | `GET /api/agent-profiles` | read |
| `oh_start_conversation` | `POST /api/conversations` | operate |
| `oh_send_message` | `POST /api/conversations/{id}/events` | operate |
| `oh_run_conversation` | `POST /api/conversations/{id}/run` | operate |
| `oh_interrupt_conversation` | `POST /api/conversations/{id}/interrupt` | operate |
| `oh_pause_conversation` | `POST /api/conversations/{id}/pause` | operate |
| `oh_switch_acp_model` | `POST /api/conversations/{id}/switch_acp_model` | operate |

List and event search keep the upstream `limit` maximum of 100. Kule's existing
`tools.max_output_bytes` still refuses an oversized serialized result rather than
truncating it.

### Launch request reduction

`oh_start_conversation` accepts only:

- `workspace: {working_dir}` — required, normalized, and required to stay below
  `KULE_OPENHANDS_WORKSPACE_ROOT`;
- `worktree` and `worktree_options` (`base`, `ref`, `branch_prefix`) — native Canvas
  worktree lifecycle, used instead of a second worktree manager;
- `initial_message` — text-only, at most 32 blocks, 32 KiB per block, 64 KiB total;
- `agent_profile_id` — required Canvas profile UUID; resolve it from
  `oh_list_agent_profiles`;
- `max_iterations` (1–1000), `max_budget_per_run`, `tags`, `autotitle`.

The adapter deliberately removes `secrets`, `secrets_encrypted`, `agent_settings`,
`agent_launch_additions`, `tool_module_qualnames`, `client_tools`, `hook_config`,
`plugins`, `agent_definitions`, `conversation_runtime`, `container`, `agent`,
`parent_conversation_id`, caller-chosen `conversation_id`, and the observability
header parameters. This excludes arbitrary ACP commands/arguments, shell hooks,
secret references, dynamic Python imports and privileged profile configuration.

`oh_send_message` is text-only and cannot set `role`; messages are always user
messages. `oh_switch_acp_model` changes only one ACP conversation's model, not a
stored profile. Unknown or extra arguments fail closed rather than being silently
dropped.

## Authorization and audit

- Kule's existing OAuth group and audit middleware remain the outer boundary.
  `read` and `operate` tags are assigned from the allowlist, not from caller input.
- A call-time target guard validates conversation UUIDs, the workspace root, worktree
  option shape, text-only messages, profile presence and model identifier syntax
  before any HTTP request.
- The shared HOME, UID and worktree are not a security boundary. The workspace-root
  check is target authorization, not process isolation; Canvas and the worker profile
  still govern what the agent can execute.
- Audit records keep routing metadata such as conversation ID, workspace path, model
  and limit. Prompt/message bodies are replaced by block count, byte count and
  SHA-256 digest.

## Leg 2 integration interface

A worker dispatcher can use only these tools:

1. `oh_list_agent_profiles` to resolve the exact ACP profile ID and its advertised
   model. Do not substitute a paid model silently.
2. `oh_start_conversation` with `workspace.working_dir` set to the task repository,
   `worktree: true`, the task branch prefix (for example
   `oh23/ws-oh-workers/`), the resolved `agent_profile_id`, and optionally a bounded
   initial task message. The response returns the real native conversation ID.
3. If an exact per-conversation model override is required,
   `oh_switch_acp_model(conversation_id, model)` with the verified catalog ID. The
   stored profile is unchanged.
4. `oh_send_message(..., run: true)` or `oh_run_conversation` to start work.
5. Poll `oh_get_conversation`, `oh_get_conversation_runtime` and `oh_search_events`
   for status, failures and the final report. Reuse native conversation state; do
   not persist a duplicate conversation database.
6. `oh_interrupt_conversation` (or `oh_pause_conversation`) for cancellation and
   timeout handling.

Leg 2 remains responsible for duplicate-dispatch handling, bounded concurrency,
branch/worktree mapping and verifying the worker's actual branch, commit, CI and PR.
This adapter only returns what Canvas reports.

## Separate Automation Service API (inventory only, not mounted)

The installed Automation package is a **separate service**, `openhands-automation`
`1.32.1`, with prefix `/api/automation/v1`. Its schema contains the expected
management endpoints:

- `GET /api/automation/v1` (list)
- `POST /api/automation/v1` (create)
- `GET|PATCH|DELETE /api/automation/v1/{automation_id}`
- `POST /api/automation/v1/{automation_id}/dispatch`
- `GET /api/automation/v1/{automation_id}/runs`

It is not part of the Canvas port 8000 schema and its generated OpenAPI declares no
security scheme; it uses separate service-key/permission dependencies. Its live base
URL, identity and deployment contract have not been verified. It is therefore not
mounted here. Direct conversation dispatch is the preferred path for ad hoc workers;
scheduled/webhook automation needs a separate reviewed fixture and credential in a
later change. Never reuse the Canvas key for that service.

## Live rollout gates (not satisfied by this PR)

- Review and merge this source, then provide an HTTPS path and a dedicated scoped
  Canvas service identity without changing the live gateway.
- Add a NetworkPolicy allowing only Kule to the Canvas management port; keep the API
  key out of Git, logs and prompts.
- Resolve #731 credential isolation before dispatching code-executing workers into the
  shared HOME trust domain.
- Exercise the allowlist, denial paths, cancellation, audit digest and a disposable
  conversation end to end. No merge, deployment, cluster mutation or production change
  is implied by this document.
