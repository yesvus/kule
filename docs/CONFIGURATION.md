# Configuration

Start with the [first-run guide](ONBOARDING.md), or use the reference example for manual configuration.

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

Host execution is disabled by default. For single-host installations without `[[hosts]]`, enabling it requires both `tools.exec_enabled = true` and `KULE_HOST_EXEC_ENABLED=1`, plus a fixed `KULE_HOST_EXEC_TARGET=user@host` (a DNS hostname or IPv4 address; no IPv6 literal, port, path or SSH options). Set `tools.timeout_seconds` to at least 15 and keep `tools.developer_enabled = false` in this runtime. A dedicated SSH identity and pinned known-hosts file are expected at `/var/run/kule-host-ssh/`. Keep the service account restricted and allow execution only to the approved identity-provider group.

## Multi-host inventory (`[[hosts]]`)

Kule supports an explicit, immutable inventory of SSH-managed hosts. When one or more `[[hosts]]` tables are defined, Kule replaces the single-host execution tool with multi-host tools:
- `host_list`: discover non-secret metadata for authorized hosts.
- `host_status`: inspect host reachability, latency, and platform details.
- `host_exec`: run bounded Bash scripts on explicitly approved hosts (conditionally registered only when BOTH global `[tools] exec_enabled = true` AND at least one host has `exec_enabled = true` with non-empty `exec_groups`).

### Host structure and fields

Each host entry supports the following tables and keys:

- `[[hosts]]`:
  - `host_id`: Unique lowercase identifier slug (`^[a-z0-9][a-z0-9._-]{0,63}$`, no `..`).
  - `transport`: Transport type, currently `"ssh"` (default: `"ssh"`).
  - `platform`: Target operating system, `"macos"` or `"linux"`.
  - `description`: Optional non-secret description (max 256 chars).
- `[hosts.ssh]`:
  - `host`: Hostname or IP address (no wildcards or embedded credentials).
  - `user`: SSH username (`^[A-Za-z_][A-Za-z0-9._-]{0,63}$`).
  - `port`: Port number between 1 and 65535 (default: 22).
  - `key_path`: Path to the dedicated SSH private key (owner-readable with no group/world-readable bits, for example mode 0600).
  - `known_hosts_path`: Path to the pinned `known_hosts` file.
- `[hosts.policy]`:
  - `read_groups`: Array of identity-provider groups allowed to see the host and query `host_status`.
  - `exec_groups`: Array of identity-provider groups allowed to run `host_exec`.
  - `exec_enabled`: Boolean flag controlling execution on this host. **Defaults to `false`**.

### Execution safety & per-host opt-in

Privileged host execution requires a two-layer opt-in:
1. **Server level**: `tools.exec_enabled = true` in `[tools]`. Defaults to `false`.
2. **Per-host level**: `exec_enabled = true` in `[hosts.policy]`, requiring non-empty `exec_groups`. Defaults to `false`.

The `host_exec` tool is registered conditionally only when BOTH the server-level `tools.exec_enabled = true` AND at least one configured host has `policy.exec_enabled = true` (with non-empty `exec_groups`). If `tools.exec_enabled = false` or no host enables execution, `host_exec` is not registered at all. For any host with `policy.exec_enabled = false`, execution calls fail closed. Developer runtime sharing remains strictly prohibited (`tools.developer_enabled = false`).

### Multi-host example configuration

```toml
# macOS workstation example (zombie)
[[hosts]]
host_id = "zombie"
transport = "ssh"
platform = "macos"
description = "macOS developer workstation"

[hosts.ssh]
host = "zombie.local"
user = "operator"
port = 22
key_path = "/var/run/kule-host-ssh/zombie_id_ed25519"
known_hosts_path = "/var/run/kule-host-ssh/known_hosts"

[hosts.policy]
read_groups = ["kule-users"]
exec_groups = ["kule-exec"]
exec_enabled = false  # exec disabled by default; per-host opt-in required

# Linux server example (gurbet)
[[hosts]]
host_id = "gurbet"
transport = "ssh"
platform = "linux"
description = "Linux production host"

[hosts.ssh]
host = "gurbet.internal"
user = "kule"
port = 22
key_path = "/var/run/kule-host-ssh/gurbet_id_ed25519"
known_hosts_path = "/var/run/kule-host-ssh/known_hosts"

[hosts.policy]
read_groups = ["kule-users", "linux-operators"]
exec_groups = ["kule-exec"]
exec_enabled = false  # exec disabled by default; per-host opt-in required
```

### Diagnostics (`kule doctor`)

Run `kule doctor` to perform an offline preflight check of your configuration:
- For each configured SSH host, verifies that `key_path` exists, is a regular file (not a symlink), is owner-readable, and has no group- or world-readable bits (for example, mode 0600).
- Verifies that `known_hosts_path` exists and is a regular file (not a symlink).
- Outputs redacted non-secret pass/fail results identified by `host_id`.
- Never displays or echoes SSH keys or secret values.


## Upgrading an existing installation

The default state directory, audit path and scratch directory retain their previous on-disk locations until an explicit migration is performed. This preserves persisted OAuth sessions, audit continuity and any existing `DISABLED` emergency-stop marker. Do not move these paths just to rename the package; set new paths explicitly only after migrating their contents and confirming the kill switch remains effective.

Existing `OPERATOR_MCP_OIDC_CLIENT_SECRET` and `OPERATOR_MCP_JWT_SIGNING_KEY` environment variables remain supported during the transition. The corresponding `KULE_*` variables are read on every installation. Non-empty `KULE_*` values take precedence; if both current and legacy values are non-empty but different, startup fails. An empty new variable falls back to its non-empty legacy counterpart. Existing deployments also require explicit updates to the executable name, container image, and config mount paths before adopting the new image.

Kule's public HTTP endpoint should normally bind to localhost behind a trusted TLS reverse proxy.
