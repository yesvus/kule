# Kule Hub

The Hub is Kule's MCP-facing service for authenticated, auditable host administration. It owns OAuth/OIDC authentication, the explicit approved-host inventory (`HostRegistry`), `caller × host × operation` fail-closed RBAC, the emergency kill switch, `HostTransport` routing, and target-aware hash-chained audit logging.

Per the staged architecture ([`yesvus/kule#60`](https://github.com/yesvus/kule/issues/60)):

- **`v0.2.0`**: Routes multi-host operations through `HostTransport` using an explicit-inventory SSH adapter (Linux + macOS ARM64, pinned host keys, opt-in per-host `host_exec`).
- **`v0.3.0`**: Adds typed host operations and separately scoped, time-bound break-glass SSH grants ([`#36`](https://github.com/yesvus/kule/issues/36)).
- **`v0.4.0`**: Conditionally adds a Hub-side outbound TLS WebSocket (`wss://`) listener for minimal Kule-native agents (header/handshake auth, revocable enrollment) and an operator CLI (`kule host`, `kule grant`, `kule audit`).
- **`v0.5.0`**: Optionally adds a lightweight, owner-only Web Management UI ([`#64`](https://github.com/yesvus/kule/issues/64)) on top of the stabilized host, kill-switch, audit, and grant APIs.

The current server implementation lives in [`src/kule/`](../src/kule/). Kule remains strictly host-only (no universal MCP gateway) and preserves independent owner SSH/console recovery.

See the [architecture](../docs/architecture/host-control-monorepo.md).
