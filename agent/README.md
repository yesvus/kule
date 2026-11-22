# Kule Agent

The planned local host agent for Kule-managed machines.

**Current status:** architecture skeleton only; upstream code has **not** yet been copied or modified. Initial import must retain license/attribution/modification notices, record upstream revision, and pass a security review.

The agent runs on an explicitly enrolled host, connects **outbound** to the Hub via authenticated TLS WebSocket (`wss://`), and applies local allowlists to host commands, filesystem and service operations. Independent SSH/console recovery remains available to the owner. A disconnected or unregistered agent has no authority to run calls.

See [architecture](../docs/architecture/host-control-monorepo.md).
