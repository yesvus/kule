# Kule

**Securely control your own hosts from any compatible MCP client.**

Kule is an open-source, self-hosted **host management MCP** project. The target architecture is a single monorepo with a [Hub](hub/), a [host Agent](agent/) and their shared [Protocol](protocol/). It is **not** a general MCP gateway, plugin hub, agent orchestrator, Kubernetes MCP, Argo CD MCP or OpenHands MCP.

[Architecture and phased migration](docs/architecture/host-control-monorepo.md)

## Status

The **current implementation is transitional**: `src/operator_mcp/` still contains the former single-runtime FastMCP service and legacy Kubernetes, Argo CD, OpenHands and workspace adapters. The `hub/`, `agent/`, and `protocol/` directories currently document package ownership; they are **not yet operational packages**. Do not treat the new multi-host agent topology as deployed or tested.

## Security requirements

- Authenticated MCP endpoint with OAuth/OIDC; authorization at discovery **and** call time.
- Explicitly enrolled host identities; per-host and per-operation policy.
- Agent-enforced command, file and service allowlists. Host execution is high authority, **not** a sandbox.
- Bounded timeouts/output, audit logging with best-effort redaction (not a security boundary), emergency disable and independent owner console/SSH recovery.
- Never automatically expose all hosts, infer host authority from LLM identity, or use arbitrary client-provided target addresses.

## Running the existing legacy service

The current live endpoint, OAuth state and deployment are preserved until a reviewed migration succeeds:

```sh
pip install .
operator-mcp check-config --config /etc/operator-mcp/config.toml
operator-mcp serve --config /etc/operator-mcp/config.toml
```

Configure `server.public_url`, OIDC issuer/client settings, allowed OAuth redirect URIs, operator groups, audit/state paths and tool policy in TOML. Provide `OPERATOR_MCP_OIDC_CLIENT_SECRET` and `OPERATOR_MCP_JWT_SIGNING_KEY` through a secret manager or the process environment, never Git. Bind locally by default, terminate TLS at a trusted proxy, and leave `tools.exec_enabled = false` without explicit authority review.

## Development

```sh
pip install -e '.[dev]'
pytest -q
ruff check .
```

Apache-2.0 — see [LICENSE](LICENSE). Third-party attribution will accompany any imported agent/protocol sources.
