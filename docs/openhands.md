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
| `KULE_OPENHANDS_CA_FILE` | Optional absolute path to a readable public CA PEM bundle for the configured HTTPS listener. Required for the planned private-CA Tezgah listener. If unset, normal client TLS trust applies; if set but invalid, startup and `check-config` fail closed. |
| `KULE_OPENHANDS_REPOSITORIES` | JSON object mapping each approved canonical `owner/name` to its exact Canvas source path, for example `{"yesvus/kule":"/workspace/src/kule"}`. Required; 1–64 entries; no path root, `..`, duplicate name or duplicate path. |

The HTTP client pins the origin, disables redirects and ignores proxy environment
variables, so the service key cannot follow a redirect or an ambient proxy to another
host. The key is never a tool argument and is not written to the audit log.
An explicit CA bundle is loaded into an integration-local SSLContext with certificate
and hostname verification enabled; other Kule clients are unchanged. Mount only the
public CA, never its signing key. Do not rely on `SSL_CERT_FILE` or disable TLS
verification.

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
| `oh_get_conversation` | `GET /api/conversations/{id}` | read |
| `oh_get_conversation_runtime` | `GET /api/conversations/{id}/runtime` | read |
| `oh_search_events` | `GET /api/conversations/{id}/events/search` | read |
| `oh_get_event` | `GET /api/conversations/{id}/events/{event_id}` | read |
| `oh_list_agent_profiles` | `GET /api/agent-profiles` | read |
| `oh_start_conversation` | `POST /api/conversations` | operate |
| `oh_rename_conversation` | `PATCH /api/conversations/{id}` | operate |
| `oh_send_message` | `POST /api/conversations/{id}/events` | operate |
| `oh_run_conversation` | `POST /api/conversations/{id}/run` | operate |
| `oh_interrupt_conversation` | `POST /api/conversations/{id}/interrupt` | operate |
| `oh_pause_conversation` | `POST /api/conversations/{id}/pause` | operate |
| `oh_switch_acp_model` | `POST /api/conversations/{id}/switch_acp_model` | operate |
| `oh_switch_acp_effort` | `POST /api/conversations/{id}/switch_acp_effort` | operate |

List and event search keep the upstream `limit` maximum of 100. Kule's existing
`tools.max_output_bytes` still refuses an oversized serialized result rather than
truncating it.

### Repository scope

Every conversation tool except `oh_list_agent_profiles` requires a canonical
`repository` argument (`owner/name`, normalized to lowercase). The Canvas search API
has no repository filter, so this cannot be passed upstream:

- `oh_start_conversation` requires `repository` and forces the native tag
  `kulerepo=owner/name`. A caller-supplied `kulerepo` with another value is rejected.
  Issue, leg, task and model tags remain the session owner's responsibility.
- `oh_list_conversations` asks Canvas for one bounded page (maximum 100 items), then
  returns only items whose native `tags.kulerepo` exactly matches the requested
  repository. When a page has no match it follows a bounded number of native pages
  (at most 5), sets `truncated: true` and returns a resumable cursor if the scan
  stopped early. Legacy conversations without `kulerepo` are omitted and remain
  explicitly unclassified until an operator verifies their mapping.
- The returned continuation is an encrypted, authenticated gateway cursor
  (`gc1.*`), not Canvas's `next_page_id`. Canvas derives `next_page_id` from the next
  global conversation, which can belong to another repository, so returning it would
  disclose an excluded ID; the sealed cursor keeps every native ID opaque. The cursor
  anchors Canvas's next native position, is replayed as Canvas's native `UUID.hex`
  `page_id`, and resumes at the first unscanned conversation rather than rebuilding
  the position from a returned item. Callers pass the cursor back as `page_id`; a
  stale or tampered cursor is denied instead of silently restarting from the first
  page. A scan that reaches the page bound without a match still returns a resumable
  cursor, so the caller can continue past the bound rather than receive
  `truncated: true` with no continuation.
- List continuation is only offered for creation-time ordering
  (`CREATED_AT`/`CREATED_AT_DESC`, the default). Updated-time ordering is rejected
  because a rename can move an already-scanned conversation and skip an unread one.
  `oh_list_conversations` advertises only the stable creation-order values.
- Direct-ID reads and actions (`get`, runtime, events, event, send message, rename,
  run, interrupt, pause, model switch, effort switch) require `repository` and first
  read the native conversation tags. A missing tag, a different tag, or an unverifiable preflight is
  denied before the requested action. There is no unscoped ID bypass.
- `oh_search_events` keeps the native event filters (`kind`, `source`, `body`,
  `sort_order`, `timestamp__gte`, `timestamp__lt`) and bounded `limit`/`page_id`
  because every event belongs to the already-verified conversation.
- `oh_count_conversations` is not exposed because the upstream count endpoint cannot
  be repository-scoped without global counting.

LEG 2 owns filtering by issue, task, leg, model and status. This adapter only
enforces the repository boundary and exposes the scoped/native fields it needs; it
does not add a second session registry or database.

### Safe response projection

Conversation responses (`oh_start_conversation`, `oh_get_conversation` and the items
returned by `oh_list_conversations`) are projected to lifecycle fields before leaving
the gateway: ID, title, `execution_status`, timestamps, tags, `working_dir`/workspace
kind, iteration and budget limits, current/available model metadata, metrics and the
launched profile ID. Canvas's `ConversationInfo`
also carries the secret registry, hook definitions, agent settings and state,
blocked-action messages and a remote workspace API key; those fields are dropped even
if a future Canvas version adds them to the response. `launched_agent_profile` is
reduced to its profile ID, so `secret_refs` and `integration_refs` do not leave the
gateway. Relationship IDs (`parent_conversation_id`, `sub_conversation_ids`,
`forked_from_conversation_id`, `forked_from_event_id`, `leaf_event_id`) are also
dropped: Canvas does not verify the referenced conversation's repository tag, so
returning them would disclose an ID that a direct read would deny.

The other response shapes are not projected and are passed through as their native
Canvas types: `oh_start_conversation`/`oh_get_conversation`/list items are the only
`ConversationInfo` responses, `oh_rename_conversation`, `oh_run_conversation`,
`oh_interrupt_conversation`, `oh_pause_conversation`, `oh_send_message` and
`oh_switch_acp_model` and `oh_switch_acp_effort` return Canvas's `Success` object, `oh_get_conversation_runtime`
returns `ConversationRuntimeInfo`, `oh_list_agent_profiles` returns the profile
summary records and the event tools return native session events. Those shapes do not
contain the conversation secret registry, hook definitions, workspace API key or
profile secret references, but event payloads are session data and should still be
treated as sensitive operator content.


### Launch request reduction

`oh_start_conversation` accepts only:

- `repository` — required canonical `owner/name`; must be present in the approved
  mapping and is enforced as `kulerepo`;
- `workspace: {working_dir}` — required, normalized, and required to equal the exact
  approved path for that repository; a sibling, parent or subdirectory is rejected;
- `worktree` and `worktree_options` (`base`, `ref`, `branch_prefix`) — native Canvas
  worktree lifecycle, used instead of a second worktree manager;
- `initial_message` — text-only, at most 32 blocks, 32 KiB per block, 64 KiB total.
  Omit it when the dispatcher must verify the worktree first: Canvas can persist and
  run the message before it returns the conversation ID;
- `agent_profile_id` — required Canvas profile UUID; resolve it from
  `oh_list_agent_profiles`;
- `max_iterations` (1–1000), `max_budget_per_run` (positive and at most 1000 USD),
  `tags`, `autotitle`.

The adapter deliberately removes `secrets`, `secrets_encrypted`, `agent_settings`,
`agent_launch_additions`, `tool_module_qualnames`, `client_tools`, `hook_config`,
`plugins`, `agent_definitions`, `conversation_runtime`, `container`, `agent`,
`parent_conversation_id`, caller-chosen `conversation_id`, and the observability
header parameters. This excludes arbitrary ACP commands/arguments, shell hooks,
secret references, dynamic Python imports and privileged profile configuration.

`oh_send_message` is text-only and cannot set `role`; messages are always user
messages. `oh_switch_acp_model` changes only one ACP conversation's model, not a
stored profile. `oh_rename_conversation` accepts only `title` (1–200 characters); it
cannot rewrite tags, budgets or other metadata. Unknown or extra arguments fail
closed rather than being silently dropped.

FastMCP merges inbound MCP HTTP headers into the outbound Canvas request. The adapter
therefore sends only a fixed header allowlist of normal transport headers, rebuilds
`Host` and `Content-Length` from the configured URL and the serialized body, and
re-applies the configured service key after filtering. Caller-supplied
`X-OpenHands-Observability-Tags`, `X-Session-API-Key`, `Host`, `Content-Length`,
`Transfer-Encoding`, `Authorization`, `Cookie`, tracing headers and similar values
are removed or replaced before the request leaves the gateway, so an inbound header
cannot override the Canvas credential or the request framing.
`oh_interrupt_conversation` is the native stop operation; `oh_pause_conversation` is
the cooperative alternative.


## Authorization and audit

- Kule's existing OAuth group and audit middleware remain the outer boundary.
  `read` and `operate` tags are assigned from the allowlist, not from caller input.
- A call-time target guard validates the approved repository mapping, conversation
  UUIDs, the exact repository path, worktree option shape, text-only messages, numeric
  bounds, profile presence, model identifier syntax and effort identifier syntax before
  any action. Direct-ID actions also verify the native `kulerepo` tag with a read-only
  preflight.
- `operator-mcp check-config` validates the same enabled Canvas settings as `mount`
  when `KULE_OPENHANDS_ENABLED=1`: repository map, HTTPS origin and service key. It
  does not create a client or contact Canvas; it validates the CA bundle when set.
  When the adapter is disabled, none of those settings are required.
- Conversation responses (`oh_start_conversation`, `oh_get_conversation` and
  `oh_list_conversations` items) are projected onto the safe lifecycle schema described
  above. Other Canvas response types are returned as their native summary or event
  shapes; see the projection scope above.
- Audit metadata includes the requested repository. The repository tag is written by
  the adapter at launch; callers cannot silently relabel a conversation.
- The shared HOME, UID and worktree are not a security boundary. The exact
  repository-to-path mapping is target authorization, not process isolation; Canvas
  and the selected agent profile still govern what the session can execute.
- Audit records keep routing metadata such as conversation ID, workspace path, model
  and limit. Prompt/message bodies are replaced by block count, byte count and
  SHA-256 digest.

## Session lifecycle interface for Leg 2

The public MCP abstraction is a **session** (a native Canvas conversation). "Worker"
is a LEG 2 policy concept layered on a session; worktree and PR are optional session
attributes, not additional public lifecycle verbs. Kule must expose one lifecycle API:
these `oh_*` tools. LEG 2 should call them rather than add a second public
start/status/interrupt implementation; it may add task, issue, model, worktree and PR
policy around them.

A session dispatcher can use only these tools:

1. `oh_list_agent_profiles` to resolve the exact profile ID and agent kind. The
   profile summary does **not** guarantee an ACP model. Before dispatch, require a
   separately verified model ID (for example from the session's own
   `current_model_id`/`available_models` after start, or an owner-approved
   profile-to-model mapping). If neither is available, stop dispatch. Do not silently
   substitute a paid model.
2. `oh_start_conversation` with `repository`, `workspace.working_dir` set to that
   repository's exact approved path, `worktree: true`, the task branch prefix (for
   example `oh23/ws-oh-workers/`), the resolved `agent_profile_id`, and the session's
   `kuleissue`/`kuletask`/`kulemodel` tags as appropriate. Omit `initial_message`
   whenever a preflight check is required: Canvas persists an initial message and can
   start the agent before returning the conversation ID, so verification would happen
   too late. The response returns the real native conversation ID. Verify the
   returned workspace path and runtime availability with `oh_get_conversation` /
   `oh_get_conversation_runtime`; a conversation ID alone does not prove the worktree
   was created. Those tools do **not** report the Git branch, so branch verification
   is a prerequisite this adapter cannot satisfy. Verify the branch through a
   separately approved native source before sending work, or keep the session idle.
   If verification fails, stop the session; do not fall back to the source checkout.
3. If an exact per-conversation model override is required,
   `oh_switch_acp_model(repository, conversation_id, model)` with the verified catalog
   ID. The stored profile is unchanged. If a distinct reasoning effort is required,
   call `oh_switch_acp_effort(repository, conversation_id, effort)` with the exact
   server-reported or separately verified value (for example `high`), and re-read
   session metadata before dispatch. Do not substitute a different effort silently.
4. `oh_send_message(repository, ..., run: false)` followed by
   `oh_run_conversation(repository, ...)` when the task must start only after
   verification. `oh_send_message(..., run: true)` is a single-call alternative. If
   Canvas saves the message but rate-limits the run, the MCP caller receives a
   FastMCP tool error with `Rate limited by upstream API, please retry later`, not a
   `429` tool status. The message is already saved in that case: back off and retry
   only `oh_run_conversation` on the same conversation. Do not resend the message.
5. Poll `oh_get_conversation`, `oh_get_conversation_runtime` and `oh_search_events`
   with `repository` for status, failures and the final report. Use
   `oh_list_conversations(repository, ...)` with bounded `limit`, creation-order
   sorting and the encrypted `page_id` cursor for discovery. Reuse native
   conversation state; do not persist a duplicate conversation database.
6. Optionally `oh_rename_conversation(repository, ..., title)` for a human-readable
   label. Use `oh_interrupt_conversation(repository, ...)` (or
   `oh_pause_conversation`) for cancellation and timeout handling.

Leg 2 remains responsible for duplicate-dispatch handling, bounded concurrency,
branch/worktree mapping, issue/leg/task/model filtering and verifying the session's
actual branch, commit, CI and PR. This adapter only enforces repository scope and
returns what Canvas reports.

### Context compaction

ACP context compaction belongs to the ACP harness/profile. Canvas also exposes a
`POST /api/conversations/{id}/condense` route, but it is not part of this allowlist
and must not be assumed to manage an ACP session's context. Kule does not expose
`/condense` and does not implement another compactor. Configure compaction in the
selected ACP profile or harness, and treat a harness that cannot compact as a known
session limitation rather than adding a Kule-side summarizer. `oh_search_events` may
return native `Condensation`/`CondensationSummaryEvent` records when the harness
compacts; observing them does not give Kule a way to trigger compaction.


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
mounted here. Direct conversation dispatch is the preferred path for ad hoc sessions;
scheduled/webhook automation needs a separate reviewed fixture and credential in a
later change. Never reuse the Canvas key for that service.

## Live rollout gates (not satisfied by this PR)

- Review and merge this source, then provide an HTTPS path and a dedicated scoped
  Canvas service identity without changing the live gateway.
- Add a NetworkPolicy allowing only Kule to the Canvas management port; keep the API
  key out of Git, logs and prompts.
- Resolve #731 credential isolation before dispatching code-executing sessions into the
  shared HOME trust domain.
- Exercise the allowlist, denial paths, cancellation, audit digest and a disposable
  conversation end to end. No merge, deployment, cluster mutation or production change
  is implied by this document.
