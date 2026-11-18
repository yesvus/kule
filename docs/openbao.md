# WS-OPENBAO (#25): typed metadata onboarding and status

**Status: source-only, not wired, not live.** This change adds one OpenBao-specific
module, its mock tests and this document. It does not contact OpenBao, Kubernetes,
Vault/OpenBao APIs, a trusted executor, or any credential store. It does not add
a token, policy, role, secret value, server registry entry, configuration flag,
deployment, image or rollout.

Related: [Kule #25](https://github.com/yesvus/kule/issues/25),
[Kule #18](https://github.com/yesvus/kule/issues/18),
[ops #906](https://github.com/yesvus/ops/issues/906),
[ops #1030](https://github.com/yesvus/ops/issues/1030),
[ops #725](https://github.com/yesvus/ops/issues/725).

## 1. Why this shape

The owner needs routine secret-path onboarding without repeated OpenBao admin UI
work, while still entering externally issued secret values privately in the
OpenBao UI. The smallest useful Kule surface is therefore:

1. reserve an **empty** KVv2 metadata record for an approved exact path;
2. return the exact OpenBao UI location and the key names the owner must enter;
3. read back metadata-only status without exposing values.

Issue and delivery automation stay out of this change. They require reviewed
trusted-executor actions and the #18 `credential_*` contract, and are reported as
unsupported rather than approximated with a made-up endpoint.

This follows the #18 boundary: Kule does typed plan/status/apply and never holds
the provider or OpenBao master credential. A separately authorized trusted
executor (the existing ops #906 boundary) talks to OpenBao inside its own trust
domain and returns metadata-only outcomes.

## 2. Native KVv2 metadata semantics used

OpenBao KVv2 metadata is separate from secret data. The module relies only on the
documented native API:

- `GET /v1/{mount}/metadata/{path}` reads key metadata.
- `POST /v1/{mount}/metadata/{path}` creates or updates metadata and **does not
  create a new version**.
- `current_version == 0` means no data version exists yet; the metadata record
  can be reserved before the owner enters a value.
- `custom_metadata` is a string-to-string map. A metadata POST fully overwrites
  it, so this module reads first and merges unrelated existing keys instead of
  replacing them.
- Metadata exposes `current_version`, `created_time`, `updated_time`,
  `max_versions`, `cas_required`, `delete_version_after` and per-version
  metadata. This module projects only the top-level fields it needs and never
  requests `/data/`, `/subkeys/` or a version payload.

References:

- [OpenBao KVv2 API: create/update metadata](https://openbao.org/docs/next/api/secret/kv/kv-v2/#createupdate-metadata)
- [OpenBao KVv2 API: read secret metadata](https://openbao.org/docs/next/api/secret/kv/kv-v2/#read-secret-metadata)
- [OpenBao `kv metadata` command](https://openbao.org/docs/next/commands/kv/metadata/)

No dummy secret data version is written. That matters because a synthetic version
could flow to an ESO/ExternalSecret consumer before the owner supplies the real
value. Reservation is metadata only, not a value and not proof of value.

## 3. Tool surface

The module registers two tools only when explicitly wired:

| Tool | Tier | Purpose |
| --- | --- | --- |
| `openbao_onboarding_prepare` | `operate` | Validate an approved profile/path/keys/consumer/scope, reserve empty KVv2 metadata, return UI URL and `awaiting_value` status. |
| `openbao_status` | `operate` | Read one approved exact path's KVv2 metadata and reservation state. Never reads a value. |

Both tools carry the existing `operate` tier tag, so the current Kule policy
admits only the configured operator group (`auth.required_group`,
`mcp-gurbet-operators`). A workspace-only developer identity, a developer plus
workspace identity, an outsider and an unauthenticated caller do not see or call
them. When the #23 role registry lands, these tools should also carry
`integration:openbao` plus an operator-only capability tag; that wiring is not
added here.

### Onboarding input

`openbao_onboarding_prepare` accepts only:

- `profile`: a reviewed profile name;
- `path`: one exact KVv2 path strictly below that profile's prefix;
- `required_keys`: the exact key names the owner will enter;
- `provider_scope`: the intended provider scope, such as
  `github:yesvus/developer`;
- `consumer`: an approved consumer profile for that target;
- optional `expires_at`: a UTC `YYYY-MM-DD` date, not in the past.

There is deliberately no value, token, secret, policy, ACL, role, master-key or
arbitrary endpoint argument. The path is not a free-form secret target: it must
be canonical (no traversal, empty segment, wildcard, control character,
uppercase, leading/trailing slash or overlong segment) and strictly below the
profile prefix. A profile may also pin the required key names, in which case the
request must match that template exactly.

### Result

`openbao_onboarding_prepare` returns:

- `status`: `awaiting_value` when the metadata record has no data version, or
  `value_present_unverified` when a version already exists;
- `reservation_written`: whether this call supplied the metadata record;
- `ui_url`: built from the configured, pre-validated UI template;
- `instructions`: private-input instructions that never ask for a value in chat;
- `reservation`: only Kule's recognized metadata fields (profile, required keys,
  provider scope, consumer, expiry);
- `metadata`: bounded top-level metadata and a count of custom metadata keys;
- `value_state`, `value_read: false`, `verification: not_performed`;
- `supported_actions` and `unsupported_actions`.

If a data version already exists, `prepare` makes **no** metadata write and
returns `value_present_unverified`. Existing consumers are not silently changed.
If the path has an existing Kule reservation, `prepare` is idempotent only for
the same profile, keys, scope, consumer and expiry; a different reservation is
refused rather than overwritten. If a data version appears concurrently between
the read and reserve, the post-write read reports it as unverified. The
read/reserve sequence is not an atomic concurrency guarantee; metadata writes
never modify secret data, but the operator still needs the separate cutover
approval for an existing path.

`openbao_status` distinguishes:

- `absent`: no metadata record;
- `metadata_only`: metadata exists with no recognized Kule reservation;
- `awaiting_value`: recognized reservation and `current_version == 0`;
- `value_present_unverified`: a data version exists, but the value and provider
  permissions were not verified.

Metadata presence is never treated as proof that the right value or provider
permissions exist. A later scoped consumer check is still required.

## 4. Trusted executor contract

`src/operator_mcp/tools/openbao.py` defines a two-method protocol:

```python
class OpenBaoExecutor(Protocol):
    async def read_kv_metadata(self, *, mount: str, path: str) -> Mapping[str, Any] | None: ...

    async def reserve_kv_metadata(
        self, *, mount: str, path: str, custom_metadata: Mapping[str, str]
    ) -> None: ...
```

This is an injection contract, not an HTTP client. Kule does **not** gain an
OpenBao URL, token, CA, namespace credential or network path in this change.

The reviewed ops #906/#1030 trusted executor must expose two new fixed actions,
or an equivalent adapter with exactly these semantics, before live wiring. The
existing executor is a one-shot, image-pinned action allowlist selected through
`OPENBAO_OPERATOR_ACTION`; its current `906-readonly-eso-v1` action derives an
ESO reader policy/role and must not be overloaded to write KV metadata.

Proposed fixed action IDs for the ops review (not implemented or allowlisted
here):

| Proposed executor action | Native operation | Required constraints |
| --- | --- | --- |
| `906-openbao-kv-metadata-read-v1` | `GET /v1/{mount}/metadata/{path}` | Exact reviewed mount/path; 404 means absent; no `/data/` path. |
| `906-openbao-kv-metadata-reserve-v1` | `POST /v1/{mount}/metadata/{path}` with `custom_metadata` only | Exact reviewed mount/path; no `data` field; no version creation; merge safe custom metadata. |

Both actions must run with the existing short-lived, narrowly scoped executor
identity. They must reject an unapproved mount/path, any `/data/`, `/delete/`,
`/destroy/`, `/subkeys/`, sys, policy, auth-role or token path, and must not
return a value. Policy/role authoring is not part of these actions. The executor
admission guard, image digest, action allowlist and exact RBAC read/write paths
must be extended for these actions in the ops workstream; this Kule change
neither assumes nor performs that rollout.

The current #906 writer ACL is limited to `eso-*` role/policy authoring. It does
**not** prove that it can create KV metadata. Adding the metadata actions and
extending the ACL to the exact approved KV metadata paths is a separate ops
review and live-authorization milestone. Until that exists, the module is
source-only and the live action is unsupported.

## 5. Unsupported live actions

The module returns an explicit `unsupported_actions` map rather than pretending
to support the rest of the credential lifecycle:

- `issue`: no reviewed issuer action; must use the #18 `credential_*` contract
  and a separately reviewed trusted executor.
- `deliver`: no ESO/ExternalSecret/GitHub delivery endpoint; must use the
  reviewed #725/#1030 consumer contract.
- `rotate`: no rotation action or cutover.
- `revoke`: no revocation action or independent break-glass path.
- `policy_authoring`: arbitrary ACL/policy text is not accepted.
- `role_authoring`: OpenBao/Kubernetes role authoring is not accepted.
- `secret_read` / `secret_write`: no raw KV data path or stored value.

No URL or executor action is invented for any of these. A caller that needs them
must stop at this boundary and use the separately reviewed workstream.

## 6. UI URL validation

`OpenBaoConfig` requires an explicit `ui_secret_url_template` containing
`{mount}` and `{path}`. The template must produce an HTTPS URL with no userinfo,
query or fragment. This change does not embed or guess an OpenBao UI route. The
operator must verify the exact route against the pinned OpenBao server and mount
before enabling the tool.

Example for a verified deployment:

```text
https://openbao.example.com/ui/vault/secrets/{mount}/show/{path}
```

The generated URL contains only the approved mount and path, percent-encoded.
The module does not put a token, value or query parameter in the URL.

## 7. Wiring contract (not performed here)

Do not add the module directly in this change. #23 and #24 own the shared
registry, role/target policy, worker and server edits. After those land, the
wiring owner should:

1. Add an explicit `openbao_enabled` flag, default `false`, in the shared tool
   configuration. This change does not add config or authz edits.
2. Add a reviewed adapter that implements `OpenBaoExecutor` on top of the
   trusted executor's two fixed metadata actions. The adapter must live on the
   trusted side of the existing executor boundary, not as a Kule OpenBao client.
3. Register the module only when the flag is true and the adapter is present:

```python
from .tools import openbao

if cfg.tools.openbao_enabled:
    openbao.register(
        mcp,
        executor=trusted_openbao_executor,
        config=openbao.OpenBaoConfig(
            profiles=(
                openbao.OpenBaoProfile(
                    name="developer-github",
                    path_prefix="tezgah/github",
                    consumers=("tezgah-developer",),
                    required_keys=("token",),
                ),
            ),
            ui_secret_url_template=cfg.tools.openbao_ui_secret_url_template,
        ),
    )
```

4. Tag the tools with `integration:openbao` and an operator-only capability in
   the #23 registry. `openbao_onboarding_prepare` is a metadata write and should
   map to `Capability.CREDENTIAL_APPLY`; `openbao_status` must remain
   operator-only, not Developer `STATUS_READ`. Keep the `operate` tier tag so
   the current policy still fails closed if the #23 registry is absent.
5. Keep the module unregistered until the pinned UI route, executor actions,
   exact ACL paths, audit sink, kill switch and negative authorization tests are
   verified live.

A sample registration is not authorization to deploy. This document is not a
GitOps change and does not approve a rollout.

## 8. Security boundaries and limits

- **No secret values.** No tool argument or result carries a secret value, and
  the module never calls a `/data/` path. The owner enters values in the OpenBao
  UI. The audit log therefore contains no secret value from this module.
- **No raw policy/role.** There is no policy text, ACL body, role name, token or
  master credential field. Policy authoring remains in the guarded executor.
- **No new secrets manager, daemon or controller.** The module is one importable
  Python file with two injected metadata methods.
- **No broad enumeration.** Status is one approved exact path. There is no
  metadata list/scan operation and no cross-prefix or cross-mount access.
- **No overwrite of existing data.** A path with `current_version > 0` is
  reported and not mutated. Foreign custom metadata is preserved.
- **Metadata is not value proof.** `current_version`, `created_time` and
  `custom_metadata` do not prove the value or provider permissions. Status says
  `verification: not_performed` until a trusted scoped consumer check exists.
- **UI entry is human and private.** Instructions tell the owner not to paste
  values into chat, MCP arguments, Git, CI, logs or tickets.
- **Shared Kule controls still apply when wired.** OIDC authentication, the
  operator group, the audit chain and the `DISABLED` kill switch are inherited
  from the existing server middleware. This change does not modify them.
- **Concurrency.** Read-then-reserve is not atomic. Metadata POST does not create
  a data version, but a concurrent value write can still race the status read.
  Treat `value_present_unverified` as requiring review, not as a success.

## 9. Tests

`tests/test_openbao.py` uses only an in-memory fake executor and the existing
FastMCP/OIDC-free test harness. It covers:

- reservation of empty metadata with exact UI URL and owner instructions;
- no metadata write when a value version already exists;
- preservation of unrelated custom metadata;
- concurrent-version and unreadable-after-write outcomes;
- exact profile prefix, path, key, consumer, scope and expiry rejection;
- metadata-only status, absent/metadata-only/awaiting/present states;
- non-echo of unrecognized custom metadata;
- native `{"data": ...}` envelope handling;
- malformed executor metadata rejection;
- unsafe UI template and profile rejection;
- metadata-only executor protocol and no secret/ACL request fields;
- operator-only discovery and call-time denial through the shared middleware.

Run:

```sh
python -m pytest tests/test_openbao.py -q
python -m ruff check .
python -m ruff format --check .
```

## 10. Remaining work

- Add and review the two fixed metadata actions to the ops #906/#1030 trusted
  executor, with exact path allowlists, audit and revocation.
- Verify the pinned OpenBao UI route and input behavior for an empty metadata
  record; no dummy version.
- Build the reusable ESO reader-policy and consumer templates (#725/#1030) in
  the guarded executor, not as arbitrary ACL text in Kule.
- Wire #731's developer PAT path separately and prove the operator token is
  never delivered to Tezgah.
- Add live positive/negative authorization tests, audit evidence, kill-switch
  behavior and a second repeatable onboarding before claiming readiness.
- Report unsupported issue/deliver/rotate/revoke explicitly until those
  contracts are implemented and independently verified.
