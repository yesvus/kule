# Configuration

Kule reads non-secret settings from TOML and credentials from environment variables or an external secret manager.

Start from [`examples/config.example.toml`](../examples/config.example.toml), then configure:

- `server.public_url`: publicly reachable HTTPS origin for the MCP server
- `auth.oidc_config_url`: HTTPS OIDC discovery URL
- `auth.client_id`: OAuth client ID registered with the identity provider
- `auth.required_group`: group authorized to discover and call ordinary tools
- `auth.exec_group`: additional group required for host execution
- `audit.path`: writable JSONL audit file
- `server.state_dir`: private persistent OAuth and service state directory
- `tools.exec_enabled`: host execution enable switch; defaults to `false`

Required secret variables:

- `KULE_OIDC_CLIENT_SECRET`: OIDC client secret
- `KULE_JWT_SIGNING_KEY`: random signing key of at least 32 characters

```sh
kule check-config --config config.toml
kule serve --config config.toml
```

## Host execution

Host execution is disabled by default. For the current SSH backend, enabling it requires both `tools.exec_enabled = true` and `KULE_HOST_EXEC_ENABLED=1`, plus a fixed `KULE_HOST_EXEC_TARGET=user@host` (no port, path or SSH options). Set `tools.timeout_seconds` to at least 15 and keep `tools.developer_enabled = false` in this runtime. A dedicated SSH identity and pinned known-hosts file are expected at `/var/run/kule-host-ssh/`. Keep the service account restricted and allow execution only to the approved identity-provider group.

Kule's public HTTP endpoint should normally bind to localhost behind a trusted TLS reverse proxy.
