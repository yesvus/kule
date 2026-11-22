# Get started with Kule

Kule provides an authenticated MCP endpoint for managing an approved host. The first release uses a single configured SSH target. Setup starts with OAuth/OIDC, and host execution remains disabled until explicitly enabled.

## Requirements

- Linux or macOS, Python 3.11 or newer
- An OAuth/OIDC provider with a registered client, client ID and client secret
- An HTTPS origin for Kule's public endpoint, with a TLS-terminating reverse proxy
- A writable directory for persistent OAuth state and audit records

Configure your identity provider once during initial setup. Register Kule's own upstream OAuth callback URL, `https://mcp.example.com/auth/callback` (replace the origin with `server.public_url`), as an allowed redirect URI **in the identity provider's OAuth client**. MCP-client callback URLs are a separate layer: Kule validates them using `auth.allowed_client_redirect_uris`; do not register those MCP-client URLs in your identity provider's upstream OAuth client.

## 1. Install

~~~sh
git clone https://github.com/yesvus/kule.git
cd kule
python -m pip install .
~~~

## 2. Generate the configuration

For a terminal session, the initializer prompts for the public URL, OIDC discovery URL, and registered client ID:

~~~sh
kule init --config config.toml
~~~

For scripts and CI, supply all three without prompting:

~~~sh
kule init --config config.toml \
  --public-url https://mcp.example.com \
  --oidc-config-url https://id.example.com/.well-known/openid-configuration \
  --client-id kule \
  --required-group kule-users \
  --exec-group kule-exec
~~~

The initializer creates a configuration file with mode 0600 and private state/audit/scratch directories under .local/kule/. It refuses to overwrite an existing file or symlink. It does not register an OIDC client, save credentials, or expose new ports.

The `--required-group` and `--exec-group` options default to `kule-users` and `kule-exec`. Set them to distinct groups issued by your identity provider, and different from the reserved `mcp-workspace` and `mcp-developers` groups. Verify the generated `required_group` and `exec_group` values match your provider's groups. Host execution remains disabled by default.

## 3. Supply secrets

Set KULE_OIDC_CLIENT_SECRET from your OIDC provider, and generate **one** durable KULE_JWT_SIGNING_KEY (32 characters minimum). Keep both in your own secret manager or protected service environment; do not commit them to Git or write them to config.toml.

For example, generate a signing key locally with:

~~~sh
python -c 'import secrets; print(secrets.token_urlsafe(48))'
~~~

Store the output privately **once**. Reuse the same value after restarts; replacing it invalidates existing sessions. Export or inject the two variables before running Kule.

## 4. Verify and start

~~~sh
kule doctor --config config.toml
kule serve --config config.toml
~~~

Doctor is **offline and read-only**: it validates the local configuration, required secret presence, state directories and emergency-stop marker. It never displays secret values, probes your IdP, or executes a host command. A successful result is a local preflight, not proof of a complete remote OAuth flow.

The server binds to loopback by default. Provide a trusted HTTPS reverse proxy with a public origin matching server.public_url, then connect your MCP client to:

~~~text
https://mcp.example.com/mcp
~~~

Sign in, verify whoami from your client, and check that an unauthenticated request is denied. Verify session continuity across restart and token expiry before treating a deployment as stable.

## Container distribution

The public GHCR image is built from `Dockerfile.single-host`. It includes Python, Kule, and the OpenSSH client, while excluding the legacy Kubernetes MCP and Argo CD runtime binaries. Kubernetes, workspace, and OpenHands integrations are intentionally unavailable in this image; explicitly enabling them will fail at startup instead of returning partial tool behavior. The older `Dockerfile` remains available to maintainers working on integrations.

For a new installation, mount a persistent private volume at `/var/lib/kule`; the container runs as UID/GID `10001`, and the image provides a writable `/var/lib/kule` directory. Generate or mount the configuration at `/var/lib/kule/config.toml` (the container's default config path); state and audit directories created by `kule init` then stay under `/var/lib/kule/.local/kule`. Ensure any externally mounted volume is writable only by the intended container identity.

The initializer defaults to a loopback listener for local Python installs. For a container reached by a reverse proxy **outside** the container's network namespace, explicitly set `server.host = "0.0.0.0"` and `server.allow_pod_bind = true` in the config. Publish port 8795 only on an internal or loopback interface accessible to your TLS-terminating proxy; do not expose it publicly without HTTPS and OAuth. Keep `server.public_url` set to the external HTTPS origin.

Provide the OIDC client secret and stable JWT signing key through a protected service environment or secret manager, not in the image or config. Retain independent host recovery access. This container change does not migrate an existing deployment.

## 5. Enable a host deliberately

Read [configuration](CONFIGURATION.md#host-execution) to configure a pinned SSH identity and known-hosts file, a fixed KULE_HOST_EXEC_TARGET, distinct execution group, and explicit execution opt-in. Do not enable privileged tools until authorization and audit have been tested.

Keep independent host console/SSH recovery. The service's emergency-stop marker is in the configured state directory: DISABLED blocks tool dispatch until removed by the authorized operator.

## Maintenance

Persist and back up the OAuth state directory and signing key together. Run kule audit-verify with the audit file path to verify your audit hash chain. [Security reporting](../SECURITY.md) is available for vulnerabilities.

For the single-host release scope and release gates, see [releasing](RELEASING.md).
