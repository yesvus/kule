# Kule: host-control monorepo architecture

**Status:** Proposed architecture; implementation and deployment **not yet complete**.

## Product boundary

Kule is a self-hosted MCP server for managing **explicitly enrolled hosts**, not a universal MCP gateway, agent orchestrator, or a replacement for Kubernetes, Argo CD, OpenHands, GitHub, Grafana, or other independent MCP servers.

Kule owns the MCP connection to clients, authentication, host inventory, per-host authorization, agent sessions, routing, and audit. Each managed machine runs a local host agent that enforces its own restrictions before touching the OS. Do not route through Gurbet/Karga SSH jump chains.

## One repository, three independently versionable packages

```text
kule/
  hub/       # MCP HTTP/OAuth endpoint, inventory, agent WebSocket listener/session registry
  agent/     # Local host agent
  protocol/  # Versioned, shared agent↔hub messages/schemas
  docs/      # Architecture, operations, security, upstream attribution
  .github/   # CI that tests hub, agent, protocol and their compatibility
```

These are source directories in **one Git repository**, not submodules, externally checked-out repositories, or a fleet of MCP proxies. The existing root `src/operator_mcp` remains a **temporary legacy runtime** during migration; it must not be misrepresented as the new hub.

The upstream agent [pensados/sentinelx-cloud-core](https://github.com/pensados/sentinelx-cloud-core) and shared [pensados/sentinelx-cloud-protocol](https://github.com/pensados/sentinelx-cloud-protocol) are Apache-2.0. Reuse the maintained implementation and schemas, not the vendor's proprietary cloud hub. Retain upstream license/attributions and conspicuous modification notices; pin source revisions, track changes, and review security-impacting diffs. No deployment should connect to `mcp.sentinelx.app` or ship vendor enrollment tokens.

### Hub

- Continue FastMCP with the existing Authentik OAuth/OIDC flow. Preserve `https://mcp.yesvus.com/mcp` during controlled migration.
- Provide a server-side host inventory, enrollment, connection state, exact host ID routing, group/host/operation policy, global disable switch and audit.
- Initial client-facing tools: `host_list`, `host_info(host)`, `host_exec(host, command)`. Tools must fail closed for unknown/offline/revoked hosts and unauthorized operations.
- No generic upstream MCP mounting, plugin registry, workflow scheduler, Kubernetes API client, Argo CD proxy, OpenHands facade, or cloud credential issuer.

### Agent

- A small independently running user/service process on each enrolled Linux/macOS machine; support additional platforms only when verified.
- An **outbound-only** authenticated TLS WebSocket to the Kule hub; no inbound SSH/MCP port or SSH jump-host chain required.
- Reuse host-management primitives from the upstream agent and **local** command, path and service allowlists. The hub's permission check is additive, not a substitute for local policy.
- Explicit enrollment/rotation/revocation, distinct identity per host, bounded outputs/timeouts, no ambient root credentials, and fail-closed handling of lost connections.
- Keep local break-glass SSH/console access for the owner independent from Kule availability.

### Protocol

- Start from the pinned open-source upstream protocol schemas/bindings and adapt only where necessary.
- Strict message validation, request IDs, version compatibility, replay handling, max frame sizes, cancellation and response correlation.
- Identity tokens issued and validated by **our own Hub**, pinned to the enrolled host and revocable; never accept a third-party identity issuer as authority.
- Cross-package contract tests for handshake, invalid/expired credentials, wrong host, unauthorized operation, interrupted connection and schema drift.

## Authorization and safety invariants

1. MCP caller identity does not automatically authorize every host. Host and operation scopes are checked **on each call**, not only on discovery.
2. The agent independently enforces command/file/service allowlists; no arbitrary shell fallback to bypass them. Broad shell, if enabled, is an explicit high-risk configuration.
3. Do not allow client-supplied URLs/IPs/hostnames to select a target. Every call identifies a known enrolled host ID.
4. Identity and audit metadata must never include private key material, raw tokens or command bodies by default. Sensitive output requires explicit handling; best-effort redaction alone is not a security boundary.
5. Revoke blocks new calls immediately; define and test in-flight cancellation semantics before claiming hard kill of remote processes.
6. Admin changes, enrollment and production rollout require separately reviewed permissions; GitOps stays the source of truth for infrastructure deployment.

## Migration (all via reviewable PRs)

1. Document the boundary and monorepo directory ownership; close the obsolete gateway-topology proposal (#19).
2. Import/pin the open-source protocol and agent into `protocol/` and `agent/`, with license and upstream sync metadata. **No network enrollment or execution activation at import.**
3. Move the existing OIDC, middleware and audit code under `hub/`, implement the hub's WebSocket session registry and typed host routing, and add contract tests.
4. Remove old OpenHands/worker/workspace orchestration, Kubernetes/Argo CD proxy modules, unnecessary Docker stages, tests and docs from Kule. Stand up those MCP services separately where desired.
5. Pilot one disposable/test host with the new agent. Verify auth, reconnect/revocation, least privilege, audited calls, resource overhead and recovery, then enroll owner-approved hosts in stages.
6. Update `yesvus/ops` GitOps, network policy, Kubernetes RBAC, secrets and deployment only **after** the hub/agent acceptance gates pass. Remove legacy `KULE_K8S_UPSTREAM_ENABLED`, Kubernetes tokens and Gurbet SSH key **when no longer used**. Keep the existing OAuth state and endpoint stable during cutover.
7. Delete the root legacy runtime and compatibility code after safe rollback and real end-to-end validation.

## Definition of done

- A single public Kule monorepo contains buildable/tested `hub/`, `agent/` and `protocol/` packages.
- The Kule MCP tools manage enrolled hosts only; no other MCP services are mounted or proxied.
- Clients select `gurbet`, `karga`, `jelly`, etc. through exact logical host IDs (only once actually enrolled).
- Hub failure does not disable manual owner SSH/console recovery.
- No release or deployment is considered complete from documentation alone.
