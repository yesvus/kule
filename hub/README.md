# Kule Hub

The planned **host-only** MCP service. Its responsibility is OAuth/OIDC, authenticated host inventory and enrollment, authorized host routing, inbound agent-initiated WebSocket sessions and audit.

**Current status:** architecture skeleton only. The live compatible FastMCP implementation is still under `src/operator_mcp/` at the repository root. A reviewed migration will move its reusable auth, policy, middleware and audit here, replace the Gurbet-only SSH executor with exact enrolled-host routing, and remove Kubernetes, Argo CD, OpenHands and workspace gateway integrations.

Initial tools: `host_list`, `host_info(host)`, `host_exec(host, command)`. Each call is authorized per host and operation, fails closed for unknown, offline or revoked hosts, and remains subject to the agent's local command allowlist. Hosts must opt in through local agent enrollment; no arbitrary hostnames/SSH hop chains.

See [architecture](../docs/architecture/host-control-monorepo.md).
