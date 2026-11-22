# Kule architecture

Kule connects MCP clients to authorized operations on enrolled hosts. The architecture separates the MCP-facing service, the host-resident agent, and their shared transport contract.

## Components

### Hub

The Hub handles OAuth/OIDC, host inventory and enrollment, operation-level policy, session routing and audit events. Its MCP endpoint is exposed over HTTPS. Agents connect to a Hub-side WebSocket listener and maintain authenticated sessions.

### Agent

An agent runs on each managed host and initiates an outbound, authenticated TLS WebSocket connection (`wss://`) to the Hub. It verifies incoming requests against local command, file and service policies before executing them. Agents use distinct host identities and retain bounded resource use.

### Protocol

The versioned protocol defines enrollment identity, connection handshake, typed requests and responses, request IDs, capability negotiation, expiration and reconnection behavior. The Hub validates host identity on connection and authorizes each operation before routing it.

```text
MCP client ──HTTPS/OAuth──> Kule Hub <──outbound WSS── Host Agent
                               │                         │
                       policy + audit              local policy
                                                         │
                                                        host
```

## Security model

- The caller's OAuth identity and host/operation permissions are evaluated for each request.
- Agents separately enforce operation restrictions close to the host.
- Clients identify hosts by enrolled IDs rather than arbitrary network addresses.
- TLS, bounded timeouts, size limits and explicit revocation protect the transport.
- Audit records omit credentials and command bodies by default. Any redaction is best-effort, rather than a secret-isolation mechanism.
- Manual host recovery remains available independently of Hub availability.

## Development status

The current Python server in `src/kule/` provides OAuth/OIDC and audited operations for one configured SSH target. The dedicated Hub, Agent and Protocol implementations are being developed in the same repository. Initial compatibility and authorization tests will cover enrollment, expiry, reconnection, wrong-host routing, revocation and unauthorized operations.

The migration will preserve a verifiable upgrade and rollback path, with host agents introduced before replacing the existing SSH backend.

## Upstream source attribution

The agent and wire protocol are planned to build on the Apache-2.0-licensed [sentinelx-cloud-core](https://github.com/pensados/sentinelx-cloud-core) and [sentinelx-cloud-protocol](https://github.com/pensados/sentinelx-cloud-protocol) projects. When imported, their source revisions, license notices and modifications will be retained and documented.
