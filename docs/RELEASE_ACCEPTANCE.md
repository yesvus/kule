# v0.1.0 independent OAuth acceptance

This is a **release gate**, not an offline unit test or an instruction to operate production.
Run against a disposable Kule installation with a **fresh IdP/OIDC client, two throwaway
identities, a trusted HTTPS origin, a separate state directory and an independent
JWT signing key**. Existing Kule/Authentik deployments cannot count as evidence.

## Provision the disposable boundary

1. Pick an isolated host/container and mount a private, persistent Kule state volume.
   Install the **exact candidate wheel or SHA/digest-pinned single-host image**.
   Do not point the probe at production. Keep host execution off:
   `[tools] exec_enabled = false`, and do not set `KULE_HOST_EXEC_ENABLED`.
2. Register a **new** confidential upstream OIDC client in a **test IdP/realm**
   with redirect URI `https://YOUR-TEST-KULE-ORIGIN/auth/callback`. Grant
   `openid profile offline_access`, and configure the IdP to put the operator
   group in the `groups` claim. Choose an access-token TTL short enough to
   exercise expiry; **do not shorten production token lifetimes**.
3. Use an authorized throwaway account in `kule-users` and a second account
   **without** that group. Set `auth.required_group = "kule-users"` and a
   distinct `auth.exec_group = "kule-exec"`. The non-operator must not have
   either role. The `profile` scope must carry the groups mapping.
4. Terminate public HTTPS with a trusted certificate. Use the normal
   `server.public_url` and `auth.oidc_config_url` HTTPS settings; never
   disable TLS verification. If TLS is terminated outside the container, make
   `server.host = "0.0.0.0"` and `server.allow_pod_bind = true` **only** on
   the isolated installation, with port 8795 accessible solely to the proxy.
5. For this CLI probe alone, explicitly add the **exact** redirect to the
   disposable Kule config:
   `auth.allowed_client_redirect_uris = ["http://127.0.0.1:8765/callback"]`.
   This is the **downstream MCP client** callback; the IdP itself only needs
   Kule's upstream `/auth/callback`. Do not broaden production defaults,
   add wildcards, or open the callback port to other machines.
6. Inject `KULE_OIDC_CLIENT_SECRET` and the durable
   `KULE_JWT_SIGNING_KEY` from a test-only secret store. Do not print, echo,
   upload or commit either value. Start Kule with those values unchanged
   throughout the restart test and run `kule doctor` locally.

## Execute the read-only client probe

Install the same release candidate wheel in a **separate local Python
environment** on a machine where the operator can complete a browser login.
The probe opens a local `127.0.0.1:8765` OAuth callback and holds all tokens
in memory, not in a GitHub Actions artifact.

```sh
export KULE_ACCEPTANCE_ENDPOINT="https://YOUR-TEST-KULE-ORIGIN/mcp"
python scripts/release_oauth_probe.py --endpoint "$KULE_ACCEPTANCE_ENDPOINT" --mode anonymous

# Log in as authorized test user. When prompted, restart the disposable
# Kule service without deleting its persisted state or rotating the signing key.
# Browser login must NOT reopen on reconnect or after token expiry.
python scripts/release_oauth_probe.py --endpoint "$KULE_ACCEPTANCE_ENDPOINT" \
  --mode authorized --restart --refresh --max-expiry-wait 600

# In a separate invocation, use the wrong-group test identity. Each
# invocation holds an independent in-memory client token store.
python scripts/release_oauth_probe.py --endpoint "$KULE_ACCEPTANCE_ENDPOINT" --mode wrong-group

# Engage <state_dir>/DISABLED on the disposable server first.
# Use authorized test identity; whoami must now be denied for kill switch.
python scripts/release_oauth_probe.py --endpoint "$KULE_ACCEPTANCE_ENDPOINT" --mode stopped
# Clear DISABLED only after confirming that denial. Recheck authorized mode.
```

A valid `PASS` requires a real browser-based authorization code exchange
against the new test IdP. The authorized probe confirms `whoami`, exactly
`whoami` and `note_write` tool discovery, and the absence of `host_exec`
while execution is disabled. The denied probe requires zero visible tools and
a denied `whoami`. The stopped probe requires an authenticated `whoami`
denial attributed to the kill switch. The refresh probe waits **past the
issued token expiry**, checks access-token rotation in memory, and rejects an
unexpected second browser login. If the test IdP's TTL is longer than the
configured bound, the probe fails instead of claiming refresh succeeded.

## Additional gates and evidence

- On the disposable server, run `kule audit-verify <configured-audit-path>`
  and verify `call`, `result` and `denied` event types as appropriate,
  with no plaintext credentials/tokens in audit records. Treat audit-file
  inspection as sensitive; publish only pass/fail and event counts.
- Confirm the test client can no longer connect with a **different**
  unallowlisted localhost callback port. The current test suite validates
  DCR redirect denial synthetically; this is optional additional live evidence.
- Stop the disposable service, restore the previously pinned candidate
  image/wheel **without changing the isolated state**, and verify login and
  emergency stop behaviour where compatible. Otherwise restore the backup
  volume and demonstrate fresh recovery. Record which rollback path was
  actually tested; never claim a rollback from a Docker build alone.
- Record in [#55](https://github.com/yesvus/kule/issues/55) the exact
  candidate commit, OCI index digest, run date, standalone IdP type
  (no secret configuration), results for each gate and rollback method.
  No screenshots of authorization pages, OAuth URLs, browser storage,
  token responses, JWTs, client secrets, personal identities or raw audit logs.

**Failure is a release blocker.** This document and the probe are acceptance
instructions, **not evidence that real OAuth testing has occurred**.
No tag, GitHub Release or production promotion until the independent check is
actually performed and reviewed.
