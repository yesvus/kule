# operator-mcp

A small, self-hosted [MCP](https://modelcontextprotocol.io) server for a restricted
operator pilot. It exposes tools to an AI client over Streamable HTTP, and every call
is authenticated, authorized by group membership, and recorded in a tamper-evident
audit log. The first release intentionally has **no host shell or Kubernetes access**.\nIt does not replace existing break-glass or remote management tools.

## Status

**P1 spike. Not production.** The only tools today are `whoami` (read) and
`note_write` (writes a note into a scratch directory). They exist to prove the
authentication, authorization and audit paths end to end. There are no shell or
host-changing tools yet, and the exec tier is wired but unused.

## Architecture

- **Authentication.** FastMCP's OIDC proxy performs OAuth 2.1 with PKCE (S256) against
  your OpenID Connect provider. The server issues its own tokens, and dynamic
  client registration only accepts redirect URIs in
  `allowed_client_redirect_uris`. The default list covers ChatGPT and the\n  documented exact Claude.ai manual OAuth-client callback; validate both client\n  flows end to end before public exposure.
- **Authorization.** The token's groups claim decides access. Each tool carries exactly
  one tier tag:
  - `read`: needs `required_group`.
  - `operate`: needs `required_group`.
  - `exec`: needs `required_group` and `exec_group`, and `tools.exec_enabled = true`.
  Anything not allowed is hidden from the tool list and denied at call time.
- **Kill switch.** If the file `<state_dir>/DISABLED` exists, every tool call is refused.
  Remove the file to re-enable. The refusal is audited.
- **Audit log.** Append-only JSONL. Each record stores the SHA-256 of the previous line.
  Verify with `operator-mcp audit-verify <path>`. Call arguments and error details are
  passed through best-effort secret redaction before they are written.
- **Network.** The server binds to loopback by default. A Pod may opt into\n  `host = "0.0.0.0"` with `allow_pod_bind = true` only behind a ClusterIP,\n  restricted NetworkPolicy and approved TLS ingress; it does not expose host networking.

## Security model: what this does NOT protect against

- **Exec-group callers are effectively the service user.** Anyone in `exec_group` who
  can reach an exec tool has the service account's full power on the host. Keep that
  group tiny, and treat membership as root-equivalent.
- **OAuth is not a sandbox.** Authentication says who is calling; it does not limit
  what a permitted tool can do once it runs.
- **Timeouts stop waiting, not work.** A tool that blocks in a worker thread keeps
  running after its deadline; tools that run commands must enforce their own
  subprocess timeouts and kill the process.
- **Redaction is best-effort.** Known token shapes and `key=value` secrets are masked.
  Unusual secret formats can still reach the audit log or tool output. Tools must not
  read secrets in the first place.
- **The newest audit record is unprotected.** The chain only covers lines that have a
  successor, so truncating or editing the tail is not detectable from the file alone.
- **The audit chain detects tampering; it does not prevent it.** A host administrator
  (root) can rewrite the whole file and recompute the chain. Ship the log off the host
  for stronger guarantees.
- **Compromise of the identity provider or the reverse proxy** is outside this server's
  control. Protect those systems as you would the host.

## Configuration

Non-secret settings live in TOML. Secrets come only from the environment.

```toml
# /etc/operator-mcp/config.toml
[server]
host = "127.0.0.1"                     # default; Pod may use 0.0.0.0\nallow_pod_bind = false                  # true only for an isolated Pod listener
port = 8795
public_url = "https://mcp.example.com" # https only; the reverse proxy serves this
state_dir = "/var/lib/operator-mcp"    # DISABLED kill-switch file lives here

[auth]
oidc_config_url = "https://id.example.com/.well-known/openid-configuration"
client_id = "operator-mcp"
required_group = "mcp-operators"
exec_group = "mcp-exec"
groups_claim = "groups"
# allowed_client_redirect_uris = [...]  # defaults to ChatGPT + exact Claude callback

[audit]
path = "/var/log/operator-mcp/audit.jsonl"

[tools]
exec_enabled = false
scratch_dir = "/var/lib/operator-mcp/scratch"
timeout_seconds = 30       # 1 to 110
max_output_bytes = 65536  # 1024 to 1048576; larger results are refused and audited
```

Required environment variables (never put these in the file):

| Variable | Purpose |
| --- | --- |
| `OPERATOR_MCP_OIDC_CLIENT_SECRET` | OIDC client secret |
| `OPERATOR_MCP_JWT_SIGNING_KEY` | Signing key for issued tokens, at least 32 characters |

Check the configuration without starting the server:

```sh
operator-mcp check-config --config /etc/operator-mcp/config.toml
```

## Running locally

Requires Python 3.11 or newer.

```sh
pip install .
export OPERATOR_MCP_OIDC_CLIENT_SECRET=...           # from your IdP
export OPERATOR_MCP_JWT_SIGNING_KEY="$(openssl rand -hex 32)"
operator-mcp serve --config ./config.toml            # listens on 127.0.0.1:8795/mcp
```

Put a reverse proxy in front of it that forwards `https://mcp.example.com` to
`127.0.0.1:8795`. Clients discover the OAuth endpoints from `public_url`.

## Development

```sh
pip install -e '.[dev]'
pytest -q
ruff check .
ruff format --check .
```

The test suite includes an integration test of the HTTP auth path against a fake OIDC
provider on loopback, so it needs no network access.

## License

Apache License 2.0. See [LICENSE](LICENSE).
\n## k3s dual-client pilot (ops #461)\n\nThe deployment definitions and approval gates live in `yesvus/ops` under\n`cluster/operator-mcp-pilot/`. The client URL will be\n`https://mcp.yesvus.com/mcp`; do not expose this endpoint until the Authentik\nMFA fresh-login gate (#803), verified image digest and protected-route review pass.\n\n- ChatGPT: OAuth DCR with only the documented redirect URI patterns. Check\n  the exact callback selected by the ChatGPT plugin builder; write-tool support\n  must be proven on the **actual account**.\n- Claude.ai: prefer its published client identity when compatible; otherwise\n  choose automatic registration, with an exact fallback callback\n  `https://claude.ai/api/mcp/auth_callback`. Never permit a wildcard Claude domain.\n- The FastMCP OAuth storage backend must be explicitly verified on Linux.\n  A data directory alone does **not** prove that DCR registrations survive\n  process restarts. Reconnect/re-register and token lifecycle are acceptance tests.\n- Scratch notes, audit records and the kill switch use an isolated volume.\n  Audits redact secrets best-effort; they must not be treated as durable external\n  evidence until exported to the logging pipeline.\n- No developer-agent credentials, Docker socket, host paths, kubeconfig,\n  service-account token or host-operation tools are part of this pilot.\n