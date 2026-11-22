# Kule Agent

The planned local host agent, adapted from [pensados/sentinelx-cloud-core](https://github.com/pensados/sentinelx-cloud-core) (Apache-2.0).

**Current status:** architecture skeleton only; upstream code has **not** yet been copied or modified. Initial import must retain license/attribution/modification notices, record upstream revision, and pass a security review.

The agent runs on an explicitly enrolled host, connects **outbound** to our Hub via authenticated WebSocket, and applies local allowlists to host commands, filesystem and service operations. Independent SSH/console recovery remains available to the owner. A disconnected or unregistered agent has no authority to run calls.

Do not use a hosted SentinelX enrollment token or route to the proprietary SentinelX cloud hub.

See [architecture](../docs/architecture/host-control-monorepo.md).
