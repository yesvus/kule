# Kule

**Securely control your own host from any compatible MCP client.**

Kule is a self-hosted [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for authenticated host administration. It is **not** a general MCP gateway, plugin hub, or agent orchestrator.

## Security

- OAuth/OIDC authentication and server-enforced, group-based permissions.
- Explicitly authorized operations and targets, with audit logging and a kill switch.
- Host execution is **disabled by default**. Enabling it grants significant authority to the permitted service identity; use least privilege.
- Tool availability depends on deployment configuration. Authentication is not a sandbox, and audit redaction is best-effort.

## Run

Requires Python 3.11+ and an OIDC provider.

```sh
pip install .
operator-mcp check-config --config /etc/operator-mcp/config.toml
operator-mcp serve --config /etc/operator-mcp/config.toml
```

Configure the HTTPS `server.public_url`, OIDC issuer/client, allowed OAuth redirect URIs, operator groups, audit/state paths, and tool policy in TOML. Supply `OPERATOR_MCP_OIDC_CLIENT_SECRET` and `OPERATOR_MCP_JWT_SIGNING_KEY` through a secret manager or the process environment, **never Git**. Bind locally by default and terminate TLS at a trusted proxy.

Keep `tools.exec_enabled = false` until host access, identity and isolation have been explicitly reviewed.

## Scope

Kule controls approved hosts. Use independent, upstream MCP servers for GitHub, Grafana, Anki, OpenHands and other services; Kule does not proxy or aggregate them.

## Development

```sh
pip install -e '.[dev]'
pytest -q
ruff check .
```

Apache-2.0 — see [LICENSE](LICENSE).
