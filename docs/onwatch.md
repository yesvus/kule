# OnWatch quota integration (source-only)

Status: **source-only**. The module, tests and this document do not deploy,
restart or reconfigure Tezgah, OnWatch, Prometheus or Kule. `tools/onwatch.py`
is not added to `server.build_server` yet. That keeps this change out of the
shared server registry and the three #23 worker/auth/registry workstreams.

## Why this source

The integration uses the existing authenticated OnWatch Prometheus endpoint
`/metrics`. There is no upstream OnWatch MCP server, and the OnWatch web routes
observed in the issue returned SPA fallbacks rather than a stable read-only
contract. The module performs one bounded HTTP read per tool call; it does not
run a background scraper, queue, daemon, database or provider SDK.

Upstream semantics were checked at tag `v2.14.13`
(`dcc803348ef089068470214bf7556454656b6ace`):

- [`docs/PROMETHEUS_METRICS.md`](https://github.com/onllm-dev/onWatch/blob/v2.14.13/docs/PROMETHEUS_METRICS.md)
- [`internal/metrics/metrics.go`](https://github.com/onllm-dev/onWatch/blob/v2.14.13/internal/metrics/metrics.go)
- [`docs/OPENCODE_SETUP.md`](https://github.com/onllm-dev/onWatch/blob/v2.14.13/docs/OPENCODE_SETUP.md)

Confirmed metric semantics:

| Metric | Meaning | Important limitation |
| --- | --- | --- |
| `onwatch_quota_utilization_percent` | Current utilization, 0-100. | Provider-specific quota identifiers appear in `quota_type`. |
| `onwatch_quota_reset_timestamp_seconds` | Absolute Unix seconds of the next reset. | Omitted when no reset is scheduled. A past value can persist even while polling is healthy. |
| `onwatch_agent_healthy` | `1` for recent poll data, `0` for stale. | Poll freshness only, **not** OAuth validity or quota-data freshness. |
| `onwatch_agent_last_cycle_age_seconds` | Seconds since the last successful poll. | Companion signal; not a snapshot timestamp. |
| `onwatch_account_info` | Join metric mapping numeric accounts to human names. | The numeric `account_id` is never returned by Kule. |

The exporter refreshes from OnWatch's SQLite store on each scrape. Most quota
gauges are reset each scrape, so an unconfigured provider disappears instead of
reporting a false zero.

## Tool surface

When registered, the module exposes three read-tier tools:

- `onwatch_quota_status(provider=None)` — provider/account/window status with
  utilization, remaining percent, reset time and explicit status/reasons.
- `onwatch_quota_health()` — polling health and stale-window counts.
- `onwatch_providers()` — bounded provider, account-alias and window names.

All tools are annotated `readOnlyHint: true`, accept no credential arguments,
and return bounded data. The HTTP body is capped at 512 KiB, parsed quota
series at 5000, returned providers at 100 and windows at 300. Redirects are
refused so the bearer token cannot follow a second origin.

### Status model

Per provider account:

- `health: fresh` — `onwatch_agent_healthy == 1`.
- `health: stale` — `onwatch_agent_healthy == 0`.
- `health: unknown` — the health series is absent or invalid.

Per provider/window:

- `status: stale` — polling is stale, or the reset timestamp is more than 900
  seconds in the past. The 900-second grace matches upstream's
  `OnwatchQuotaResetMissed` alert.
- `status: unknown` — utilization, reset or health data is missing, invalid or
  outside 0-100. Missing reset data is reported as `reset_status:
  not_scheduled`; it is never interpreted as unlimited quota.
- `status: fresh` — utilization is valid, health is fresh, and any reset is in
  the future or within the grace window.

This is intentional: healthy polling does **not** make an old reset timestamp
fresh. The issue recorded reset timestamps months in the past while `codex`,
`anthropic` and `antigravity` reported health `1`; those windows are returned
as stale and must not be used for dispatch.

Account aliases come only from `onwatch_account_info`. Raw numeric account IDs
and the metrics token are not included in tool output. When no alias exists,
the output uses stable `account-1`, `account-2` labels derived from sorted
non-visible IDs.

## Configuration

The integration is off unless the metrics origin is set.

| Variable | Purpose |
| --- | --- |
| `KULE_ONWATCH_URL` | Fixed OnWatch origin, for example `http://127.0.0.1:9211`. HTTPS is required except for loopback HTTP. No path, query, fragment or userinfo. |
| `KULE_ONWATCH_TOKEN_FILE` | Mounted file containing the existing metrics bearer token. Never pass the token as a tool argument or put it in Git. |

Set the endpoint and token through the existing secret-delivery/GitOps path;
this change does not create or rotate either. If the token file is unset, the
request is unauthenticated; the authenticated deployment should set it.

## Proposed Kule wiring

Add one call after the shared tool registry stabilizes:

```python
from .tools import onwatch

# build_server(...)
onwatch.register(mcp, timeout_seconds=cfg.tools.timeout_seconds)
```

`register` itself is a no-op when `KULE_ONWATCH_URL` is unset, so an image can
include the module without exposing tools by default. Do not add it directly in
this change: #23 owns the shared registry/auth/worker edits.

## Proposed #23 worker-selection hook

No worker registry or selection policy is changed here. After wiring, the
worker selector should:

1. Map each ACP profile/model ID to an explicit OnWatch provider and window
   (`provider` + `quota_type`). This mapping is operator configuration; the
   repository does not contain enough data to invent it.
2. Call `onwatch_quota_status(provider=...)` before dispatch and require the
   selected window to be `status: fresh`.
3. Require `remaining_percent` to stay above a configurable reserve after the
   requested concurrency is admitted.
4. Treat `stale`, `unknown`, absent providers/windows, and reset data older than
   the grace window as ineligible.
5. Use only an operator-configured fallback list. Never fall back silently to a
   paid/overage model and never treat missing telemetry as unlimited capacity.

A mapping to `opencode_go` must remain disabled until the follow-up below is
verified. A negative fixture test asserts that an absent provider is `unknown`,
not available.

## OpenCode Go follow-up

OnWatch v2.14.13 supports polling OpenCode Go
([`docs/OPENCODE_SETUP.md`](https://github.com/onllm-dev/onWatch/blob/v2.14.13/docs/OPENCODE_SETUP.md)),
but its Prometheus exporter does not emit OpenCode Go series. `Scrape()` in
`internal/metrics/metrics.go` calls the anthropic, codex, copilot, zai, minimax,
antigravity, gemini, openrouter, moonshot, deepseek and API-integration
scrapers; there is no OpenCode Go scraper. This was also missing from v2.14.14,
v2.14.17 and `main` when checked.

Therefore this module does not invent an `opencode_go` series and does not
assume the initial `opencode-go/deepseek-v4.1-flash` profile has quota data.
Scoped follow-up:

- Add and review an upstream OpenCode Go metrics exporter (or verify a later
  pinned release that provides one).
- Confirm the window names for the 5-hour, weekly and monthly meters.
- Fix the Prometheus target/scrape path through ops#798 and verify real series
  before enabling worker dispatch.
- Keep the integration dark until those checks pass.

## Verification gap

The issue's live metadata was not re-queried here: this work must not access
live infrastructure or credentials. Before enabling, operators still need to:

- verify the Prometheus target and token mount reach the OnWatch endpoint;
- confirm actual reset timestamps and current snapshot freshness;
- confirm the scoped OpenCode Go blocker above;
- run a read-only query through Kule under an authorized operator identity and
  a negative unauthorized query.

Until then, the source, fixtures and this document are the reviewed boundary.
