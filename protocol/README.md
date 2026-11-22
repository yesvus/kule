# Kule Agent–Hub Protocol

The planned versioned wire contract between Kule Hub and Kule Agent.

**Current status:** architecture skeleton only. The upstream [pensados/sentinelx-cloud-protocol](https://github.com/pensados/sentinelx-cloud-protocol) is **open-source Apache-2.0** and explicitly documents alternative hub implementations. Import/pin the upstream schemas and typed Python bindings with attribution; maintain our own compatible extensions behind reviewed versions.

Core contract: authenticated `hello` with host identity and negotiated version, typed `request` / `reply` messages correlated by ID, bounded outputs, reconnect/replay handling, revocation, expiry and protocol compatibility tests. Hub signs and validates Kule enrollment identities; the upstream proprietary hub is not involved.

See [architecture](../docs/architecture/host-control-monorepo.md).
