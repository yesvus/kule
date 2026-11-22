# Kule Agent

The planned host-resident process for Kule-managed machines.

Each agent is designed to initiate an outbound authenticated TLS WebSocket (`wss://`) session to its Hub, identify its enrolled host, and enforce local allowlists for command, file and service operations. Unenrolled or disconnected agents will reject remote calls. Execution will be bounded by host-specific policy; independent SSH/console access will remain available to the host owner.

The dedicated agent package is in development.

See the [architecture](../docs/architecture/host-control-monorepo.md).
