# Kule Protocol

The conditional, minimal Kule-native wire contract shared between the Hub and `agent/`, planned for **`v0.4.0`** under the staged architecture ([`yesvus/kule#60`](https://github.com/yesvus/kule/issues/60)).

Multi-host operations in `v0.2.0` and `v0.3.0` run over the explicit-inventory SSH `HostTransport` adapter. `protocol/` will be implemented only if and when the `v0.4.0` outbound WebSocket agent transport is introduced.

When implemented, the versioned protocol will define:

- Hub-issued, revocable enrollment identities bound to an exact `host_id` (no external identity issuers or hosted third-party hubs).
- Header-based (`Authorization: Bearer`) or post-connect authenticated handshake frames (never URL query-parameter tokens).
- Protocol version and compatibility negotiation.
- Typed request and response messages, `request_id` correlation, capability negotiation, bounded frame sizes and timeouts, reconnection, and immediate revocation semantics.

`protocol/` will be a minimal Kule-native specification and will **not** vendor or depend on `sentinelx-cloud-protocol` or `sentinelx-cloud-core`.

**Status:** Documentation only; not yet implemented.

See the [architecture](../docs/architecture/host-control-monorepo.md).
