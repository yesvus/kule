# Kule Agent–Hub Protocol

The planned versioned wire contract between Kule Hub and Kule Agent.

**Current status:** architecture skeleton only. Import and pin the open-source upstream schemas and typed bindings with proper attribution; maintain compatible extensions behind reviewed protocol versions.

Core contract: authenticated `hello` with host identity and negotiated version, typed `request` / `reply` messages correlated by ID, bounded outputs, reconnect/replay handling, revocation, expiry and protocol compatibility tests. Hub signs and validates Kule enrollment identities; no third-party hosted Hub is part of the deployment.

See [architecture](../docs/architecture/host-control-monorepo.md).
