# Kule architecture

Kule is a self-hosted, MCP-native server for authenticated, auditable remote host administration. Per the approved roadmap ([`yesvus/kule#60`](https://github.com/yesvus/kule/issues/60)), Kule uses a **staged, transport-independent architecture (Option C)**: host identity, per-host authorization, and target-aware auditing are established first over an explicit-inventory SSH transport, with a minimal Kule-native outbound WebSocket agent introduced only if and when agent-local policy or non-tailnet NAT traversal is required.

## Core contract

All host operations flow through a transport-independent control plane in the Hub:

- **`HostRegistry`**: An explicit, owner-approved inventory of managed hosts with stable `host_id`s, platform metadata (`linux`, `macos`), transport configuration, and per-host policy (`read_groups`, `exec_groups`, `exec_enabled` defaulting to `false`). Duplicate `host_id`s, wildcard targets, and arbitrary network addresses are rejected.
- **`HostTransport`**: An async transport interface decoupling MCP tools and policy enforcement from how the Hub reaches a host (reachability/status, bounded read-only operations, and bounded script execution with timeout, output-size, and cancellation semantics).
- **Per-host RBAC (`caller × host × operation`)**: Every request is evaluated fail-closed against the caller's OIDC identity/groups, the target `host_id`, and the requested operation (`read`, `exec`, or future typed/break-glass scopes). Unknown hosts, missing groups, wrong-host requests, disabled capabilities, or an active kill switch deny the call.
- **Target-aware hash-chained audit**: Every decision and execution records `host_id`, `transport`, `request_id`, and optional `grant_id` alongside caller, tool, timing, and outcome in a verifiable hash-chained JSONL log.

```text
                                                      ┌──> Explicit-inventory SSH (v0.2.0)
                                                      │    Linux + macOS ARM64, pinned host keys
MCP client ──HTTPS/OAuth──> Kule Hub ──HostTransport──┤
                               │                      └──> Outbound WSS Agent (v0.4.0, conditional)
                     HostRegistry + RBAC                   minimal Kule-native protocol/ + agent/
                     kill switch + audit                   header/handshake auth + local policy
```

## Components

### Hub (`hub/`, currently `src/kule/`)

The Hub is Kule's MCP-facing service over HTTPS. It owns OAuth/OIDC authentication, `HostRegistry`, `caller × host × operation` authorization, the emergency kill switch, `HostTransport` routing, and target-aware hash-chained audit logging. In `v0.4.0`, the Hub adds an operator CLI (`kule host`, `kule grant`, `kule audit`) and, if needed, a WebSocket listener for outbound agents.

### Explicit-inventory SSH transport (`v0.2.0`)

The initial multi-host `HostTransport` adapter connects to explicitly configured hosts over hardened SSH: pinned `known_hosts`, dedicated per-host identity keys, fixed `user@host`, `StrictHostKeyChecking=yes`, `ClearAllForwardings=yes`, `IdentityAgent=none`, `BatchMode=yes`, and `IdentitiesOnly=yes`. Timeout and output bounds are enforced portably for both Linux and stock macOS ARM64 (without assuming GNU `/usr/bin/timeout` on the target host). Per-host `host_exec` is opt-in and disabled by default.

### Agent (`agent/`, conditional in `v0.4.0`)

If future requirements demand agent-local policy enforcement or reaching hosts behind NAT without Tailscale/SSH, a minimal Kule-native agent will run on managed hosts and initiate an outbound TLS WebSocket (`wss://`) connection to the Hub. The agent will authenticate with Hub-issued revocable enrollment credentials, bind strictly to its enrolled `host_id`, enforce local allowlists and resource limits, and fail closed when unenrolled, disconnected, or revoked.

### Protocol (`protocol/`, conditional in `v0.4.0`)

If `agent/` is introduced, `protocol/` will define a minimal Kule-native versioned wire contract: `Authorization: Bearer` header or post-connect authenticated handshake frames (never URL query-parameter tokens), revocable Hub-issued enrollment identities, typed request/response messages, `request_id` correlation, protocol version and compatibility negotiation, capability negotiation, bounded frame sizes and timeouts, reconnection, and immediate revocation. External identity issuers will not be accepted for agent enrollment.

## Staged roadmap

| Milestone | Scope |
| --- | --- |
| **`v0.1.0` — Single-host Foundation** | Current Python MCP server in `src/kule/` with OAuth/OIDC, group-based authorization, hash-chained audit, emergency kill switch, and bounded SSH execution against a single configured target. |
| **`v0.2.0` — Multi-host Core** | Transport-independent `HostRegistry` and `HostTransport` contract, `caller × host × operation` fail-closed RBAC, target-aware hash-chained audit, and explicit-inventory multi-host SSH transport (Linux + macOS ARM64, pinned host keys, opt-in per-host `host_exec`). |
| **`v0.3.0` — Typed Host Operations & Break-glass** | Typed host operations (system, service, process, file inspection/actions) and separately scoped, time-bound break-glass SSH grants with explicit owner activation, TTL expiry, and immediate revocation ([`#36`](https://github.com/yesvus/kule/issues/36)). |
| **`v0.4.0` — Outbound Agent & Operator CLI** | Conditional minimal Kule-native outbound WSS `protocol/` and `agent/` (header/handshake auth, revocable enrollment, agent-local policy) plus an operator CLI (`kule host`, `kule grant`, `kule audit`) and optional private MCP tunnel deployment support. |
| **`v0.5.0` — Web Management UI** | Optional lightweight, owner-only Web Management UI ([`#64`](https://github.com/yesvus/kule/issues/64)) for host overview, kill switch, audit viewer, and break-glass grant controls — built strictly on stabilized `v0.2.0`–`v0.4.0` APIs. |

## Security guarantees

- **Fail-closed authorization**: Unknown `host_id`, missing group membership, wrong-host routing, disabled per-host capabilities, host-key mismatch, expired/revoked grants, and an active kill switch all deny execution.
- **Explicit host inventory**: Clients address hosts only by approved `host_id`s, never by arbitrary hostnames, IP addresses, or wildcards. SSH forwarding and agent forwarding are disabled.
- **Opt-in execution**: Remote shell execution (`host_exec`) is disabled by default both globally (via the global `[tools] exec_enabled` switch) and per host (via the per-host `exec_enabled` flag). Both must be explicitly enabled for execution to be permitted, and enabling execution on one host never grants access to another.
- **Transport and auth hygiene**: Outbound WSS agents (when implemented in `v0.4.0`) must authenticate via `Authorization: Bearer` headers or post-connect authenticated handshake frames — never URL query parameters that can leak into proxy logs. Revocation must block new calls immediately; in-flight cancellation semantics must be verified before claiming remote process termination.
- **Auditing and redaction**: Audit events include `host_id`, `transport`, `request_id`, and optional `grant_id`. Audit records omit credentials and command bodies by default. Redaction is best-effort rather than a secret-isolation mechanism; protect audit logs from unauthorized modification.
- **Independent recovery**: Owner SSH/console recovery must remain independent of Kule Hub, OIDC, or gateway availability. Kule must never become the sole recovery path to a host.

## Scope boundaries and rejected dependencies

- **Host-only product boundary**: Kule specializes in secure, MCP-native host management. It is not a universal MCP proxy/gateway, not an agent orchestrator, and not a replacement IAM or Tailscale ACL control plane.
- **No anonymous or mixed-auth host access**: Privileged host tools and sensitive host inventory require authenticated OIDC callers.
- **No SentinelX dependency**: Kule explicitly does **not** vendor or depend on `sentinelx-cloud-core` or `sentinelx-cloud-protocol`, and will never connect to vendor-hosted enrollment endpoints (`mcp.sentinelx.app`) or ship upstream enrollment tokens. Upstream query-parameter WebSocket token auth, broad non-host handler surface, and rapid protocol churn make a minimal Kule-native `protocol/` and `agent/` safer and cheaper to maintain when `v0.4.0` is needed.

## Development status

The active implementation lives in [`src/kule/`](../../src/kule/). `hub/`, `agent/`, and `protocol/` currently hold architecture documentation while `v0.2.0` builds the transport-independent `HostRegistry`, `HostTransport`, and explicit-inventory multi-host SSH adapter.
