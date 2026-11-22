# Kule Agent

The planned host-resident process for Kule-managed machines.

Each agent initiates an outbound authenticated TLS WebSocket (`wss://`) session to its Hub, identifies its enrolled host, and applies local allowlists to command, file and service operations. Execution remains bounded and subject to host-specific policy.

The dedicated agent package is in development.

See the [architecture](../docs/architecture/host-control-monorepo.md).
