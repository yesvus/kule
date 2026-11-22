# Kule architecture

Kule connects MCP clients to authorized host operations. The multi-host architecture below is the target design; the Hub/Agent transport and enrollment lifecycle are not implemented yet.

## Components

### Hub

The Hub will handle OAuth/OIDC, host inventory and enrollment, operation-level policy, session routing and audit events. Its MCP endpoint will be exposed over HTTPS. Agents will connect to a Hub-side WebSocket listener and maintain authenticated sessions.

### Agent

An agent will run on each managed host and initiate an outbound, authenticated TLS WebSocket connection (`wss://`) to the Hub. It will verify incoming requests against local command, file and service policies before executing them. Agents will use distinct host identities and bounded resource limits.

### Protocol

The versioned protocol will define enrollment identity, connection handshake, typed requests and responses, request IDs, capability negotiation, expiration and reconnection behavior. The Kule Hub will issue and validate revocable enrollment identities, bind each credential to an exact enrolled host, authenticate agents on connection and authorize every operation before routing it. External identity issuers will not be accepted for agent enrollment.

```text
MCP client ──HTTPS/OAuth──> Kule Hub <──outbound WSS── Host Agent
                               │                         │
                       policy + audit              local policy
                                                         │
                                                        host
```

## Target security model

- The Hub will evaluate the caller's OAuth identity and host/operation permissions for each request.
- Agents will independently enforce operation restrictions on the host.
- Clients will identify hosts by enrolled IDs rather than arbitrary network addresses.
- TLS, bounded timeouts, frame-size limits and explicit revocation will protect the transport. Revocation must block new calls immediately; in-flight cancellation semantics must be tested before claiming remote process termination.
- Audit records will omit credentials and command bodies by default. Any redaction remains best-effort, rather than a secret-isolation mechanism.
- Manual host recovery will remain independent of Hub availability.

## Development status

The current Python server in `src/kule/` provides OAuth/OIDC and audited operations for one configured SSH target. The dedicated Hub, Agent and Protocol implementations are being developed in the same repository. Initial compatibility and authorization tests will cover enrollment, expiry, reconnection, wrong-host routing, revocation and unauthorized operations.

The migration will preserve a verifiable upgrade and rollback path, with host agents introduced before replacing the existing SSH backend.

## Upstream source attribution

The agent and wire protocol are planned to build on the Apache-2.0-licensed [sentinelx-cloud-core](https://github.com/pensados/sentinelx-cloud-core) and [sentinelx-cloud-protocol](https://github.com/pensados/sentinelx-cloud-protocol) projects. Their source revisions will be pinned, upstream license and modification notices retained, and security-impacting diffs reviewed. Agent identities and enrollment will be issued exclusively by the Kule Hub; deployments must not connect to the vendor-hosted `mcp.sentinelx.app` endpoint or ship upstream enrollment tokens.
