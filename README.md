# Kule

**Your personal MCP gateway.**

Connect your AI agents to your tools, services, and infrastructure — on your terms.

Kule is an open-source, self-hosted gateway for the [Model Context Protocol](https://modelcontextprotocol.io) (MCP). It provides a common access layer for MCP-compatible clients, with optional integrations, identity-based authorization, and auditable tool calls.

## Why Kule?

- **Own your integration layer.** Run Kule on your own infrastructure and connect the clients you choose.
- **Control access.** Use your identity provider, explicit tool authorization, and narrowly scoped backend credentials.
- **Compose, don't reinvent.** Reuse upstream MCP servers and service APIs where possible; implement custom tools only when needed.
- **Keep operations accountable.** Record tool calls and authorization decisions, enforce configurable limits, and retain an emergency disable mechanism.

## Project status and direction

Kule is under active development. The current implementation uses Python and FastMCP, with OAuth/OIDC over Streamable HTTP, group-based tool authorization, auditing, and opt-in integrations. Deployment configuration determines which tools are actually available; source support does not imply that a capability is enabled or validated on every client.

The longer-term direction is a context-efficient, composable gateway: independently deployable capability servers in one open-source repository, optional progressive tool discovery, finer-grained access policies, and an owner-facing administration dashboard for client, session, and permission management. These are roadmap items, not guarantees of present functionality. Dynamic discovery and runtime changes require client compatibility and resource benchmarks.

The Python package and CLI currently retain the historical `operator-mcp` name. The commands below intentionally use that name.

## Architecture

- **Authentication.** FastMCP's OIDC proxy performs OAuth 2.1 with PKCE (S256) against
  your OpenID Connect provider. The server issues its own tokens, and dynamic
  client registration only accepts redirect URIs in
  `allowed_client_redirect_uris`. The default list covers ChatGPT and the
  documented exact Claude.ai manual OAuth-client callback; validate both client
  flows end to end before considering them fully accepted.
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
- **Network.** The server binds to loopback by default. A Pod may opt into
  `host = "0.0.0.0"` with `allow_pod_bind = true` only behind a ClusterIP,
  restricted NetworkPolicy and approved TLS ingress; it does not expose host networking.

## Security model: what this does NOT protect against

- **Exec-group callers are effectively the service user.** Anyone in `exec_group` who
  can reach an exec tool has the service account's full power on the host. Keep that
  group tiny, and treat membership as root-equivalent.
- **OAuth is not a sandbox.** Authentication says who is calling; it does not limit
  what a permitted tool can do once it runs.
- **Timeouts limit waiting, not arbitrary work.** Worker-thread calls may
  outlive cancellation. Kubernetes status reads use cancellable async HTTP
  requests with an overall deadline; future host tools need their own
  process-level timeouts and termination.
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
host = "127.0.0.1"                     # default; Pod may use 0.0.0.0
allow_pod_bind = false                  # true only for an isolated Pod listener
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

## Deployment notes

- Validate OAuth registration, exact redirect URI allowlists, refresh and reconnect on each intended MCP client.
- Keep OAuth state, audit logs and emergency controls in appropriately protected persistent storage. Export audit records when stronger external evidence is required.
- Enable integrations deliberately; use scoped backend identities, least-privilege grants and restricted network access. Do not place broad host or provider credentials in a default deployment.
- Verify actual discovery, invocation, denied operations and restart behavior before enabling access. Deployment-specific topology and operational records belong outside the public project documentation.

## Optional Kubernetes read-only overview

`k8s_overview` is registered **only** when the operator explicitly supplies
`KULE_K8S_API_URL` (for example,
`https://kubernetes-api.internal:6443`). The public OAuth server cannot choose an
arbitrary Kubernetes API path or HTTP method. The fixed internal API requests
list Nodes, Pods and Deployments; results are projected to aggregate status
fields only and refuse a paginated or oversized list rather than silently
claiming a partial healthy cluster.

To run safely, GitOps must mount a short-lived, projected Kubernetes
ServiceAccount token and the cluster CA at `/var/run/kule-k8s/token` and
`/var/run/kule-k8s/ca.crt`. The ServiceAccount must retain
`automountServiceAccountToken: false`. Its dedicated ClusterRole grants
**only** `list` for core `nodes` / `pods` and apps `deployments`.
No `get secrets`, `pods/log`, `pods/exec`, mutating verbs or
`cluster-admin`. NetworkPolicy allows exactly
the explicitly configured control-plane private endpoint on TCP 6443;
the cluster CA validates the Kubernetes API certificate. Private IP,
network-test outcomes and runtime admission evidence belong in the ops
workstream, rather than this public code README.

Enabling this source alone does **not** restart the running MCP Pod, update
its publicly available tools, change RBAC, or authorize a rollout.
The independent GitOps PR must pass exact-head review, RBAC
`kubectl auth can-i` negatives and the live disposable token read
before replacing the existing digest. Retain an independent recovery path until the replacement functionality has been verified.
