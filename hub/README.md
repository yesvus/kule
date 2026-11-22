# Kule Hub

The Hub is Kule's MCP-facing service for authenticated host administration. It owns OAuth/OIDC, enrolled-host inventory, operation authorization, agent WebSocket sessions and audit.

The current server implementation lives in [`src/kule/`](../src/kule/). The dedicated multi-host Hub implementation is in development.

See the [architecture](../docs/architecture/host-control-monorepo.md).
