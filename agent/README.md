# Kule Agent

The conditional, minimal Kule-native host-resident agent planned for **`v0.4.0`** under the staged architecture ([`yesvus/kule#60`](https://github.com/yesvus/kule/issues/60)).

Multi-host operations in `v0.2.0` and `v0.3.0` use the explicit-inventory SSH `HostTransport` adapter and do not require an agent. `agent/` will be implemented only if and when agent-local policy enforcement or non-tailnet NAT traversal is needed.

When implemented, each agent will:

- Initiate an outbound authenticated TLS WebSocket (`wss://`) connection to the Kule Hub using `Authorization: Bearer` header or post-connect authenticated handshake frames (never URL query-parameter tokens).
- Use a Hub-issued, revocable enrollment identity bound to its exact `host_id` (no external identity issuers or third-party enrollment endpoints).
- Enforce agent-local allowlists and bounded resource limits for commands, files, and services, failing closed when unenrolled, disconnected, or revoked.
- Preserve independent owner SSH/console recovery regardless of Hub or agent state.

`agent/` will be a minimal Kule-native implementation and will **not** vendor or depend on `sentinelx-cloud-core` or `sentinelx-cloud-protocol`.

**Status:** Documentation only; not yet implemented.

See the [architecture](../docs/architecture/host-control-monorepo.md).
