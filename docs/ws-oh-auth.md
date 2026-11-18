# WS-OH-AUTH (#23 LEG 3): role/target trust boundaries - source only

**Status: source-only policy and tests. Nothing here activates a developer or
break-glass path, changes a credential, enables a live flag, deploys, or approves
an OpenHands worker launch.**

Related: [Kule #23](https://github.com/yesvus/kule/issues/23),
[Kule #18](https://github.com/yesvus/kule/issues/18),
[ops #1108](https://github.com/yesvus/ops/issues/1108),
[ops #731](https://github.com/yesvus/ops/issues/731), and
[`docs/workspace.md`](workspace.md).

## 1. Canonical roles

The canonical model is **Developer / Operator / Break-glass**. It replaces the
L0–L4 taxonomy for new work. Role comes from authenticated identity claims, never
from a model name, price, client name, ACP profile or prompt text.

| Role | Default group | Activation gates | Capability baseline |
| --- | --- | --- | --- |
| **Developer** | `mcp-developers` | `tools.developer_enabled`, `tools.developer_isolation_verified` | Workspace exec/read/write, repo read/write, PR open, bounded Kubernetes read, worker launch/status/stop |
| **Operator** | `mcp-operators` (`required_group`) | Existing OAuth group | Developer baseline plus scratch writes, Kubernetes write, Argo CD read/sync, credential plan/apply, host exec |
| **Break-glass** | `mcp-breakglass` | `tools.breakglass_enabled` plus a fresh `breakglass_exp` claim within `tools.breakglass_max_ttl_seconds` | `status.read` and `breakglass.recover` only |

Break-glass is deliberately **not** an Operator alias. It does not inherit
Developer shell or Operator production/credential capabilities. A break-glass
grant that is missing, expired, or longer than the configured maximum TTL yields
no role. Preserve an independent out-of-band recovery path; this source does not
make break-glass usable when Authentik or Kule is unavailable.

The legacy `read/operate/exec/workspace` tiers in `authz.py` remain unchanged for
existing tools so a source merge does not alter the current Operator endpoint.
Integration tools use the role/capability/target registry instead; their legacy
tier tags are ignored, so a tier tag cannot widen access.

## 2. Capability and exact-target policy

`src/operator_mcp/integrations.py` owns the registry. Every opt-in integration
declares:

- a stable lowercase `name`;
- `enabled` (default-off at construction);
- a non-secret `backend_identity` (for audit/ownership, not authentication);
- the exact capabilities it may serve;
- every target-bearing argument with an **exact** allowlist of strings.

Deny conditions at both discovery and call time:

- unknown, duplicate, or disabled integration;
- missing/duplicate integration or capability tag;
- capability not declared by that integration;
- no active role includes the capability;
- a declared target argument is missing, not a string, or outside the exact list;
- wildcard/prefix target values, which are rejected when the integration is
  registered.

Targets are resource arguments such as `repository`, `namespace`,
`acp_profile`, `host` or `profile`. Full endpoint allowlisting, Kubernetes RBAC,
GitHub App scope, Argo CD project scope and executor privileges remain
authoritative backend controls. The registry is additional application policy,
not a replacement for backend isolation.

### Small interface for LEG 1 / LEG 2

Do not edit this module or the middleware. Register your integration and tag its
tools:

```python
from operator_mcp.integrations import (
    Capability,
    Integration,
    capability_tag,
    integration_tag,
)

registry.register(
    Integration(
        name="openhands",
        enabled=False,  # live activation is a separate reviewed flag
        backend_identity="canvas/openhands",
        capabilities=frozenset(
            {Capability.WORKER_LAUNCH, Capability.WORKER_STATUS, Capability.WORKER_STOP}
        ),
        targets={
            "repository": frozenset({"yesvus/kule"}),
            "acp_profile": frozenset({"opencode"}),
        },
    )
)


@mcp.tool(
    tags={
        integration_tag("openhands"),
        capability_tag(Capability.WORKER_LAUNCH),
    }
)
async def openhands_start(repository: str, acp_profile: str) -> dict: ...
```

The server accepts a registry via
`build_server(cfg, claims_getter=..., integrations=registry)`. An empty registry
fails closed: integration tools are invisible and every direct call is denied.
Keep backend calls behind the existing endpoint allowlist and bounded result
limits. Do not add a target argument that is not declared; declare every
target-bearing argument the tool accepts.

## 3. Temporary shared-HOME risk (blocker)

Tezgah agents currently share UID 10001, a persistent HOME and the
`/workspace` tree. A Git worktree is a concurrency convenience, **not** a security
boundary. `workspace_exec` can read any file available to that UID, including
another agent's checkout, shell history or credential files. Hiding a tool from
discovery is not isolation.

The live Canvas shared HOME has not been verified clean and must be treated as
potentially containing operator GitHub CLI/SSH credential material. Do not read,
copy or change those values as part of this work. Until
[ops #731](https://github.com/yesvus/ops/issues/731) has removed or isolated the
credentials and a scoped developer GitHub identity is verified:

- `tools.developer_isolation_verified` must remain `false`;
- the general Developer role stays empty even if the developer group and
  `tools.developer_enabled` are present;
- do not dispatch autonomous PR-producing workers or enable `workspace_exec`
  for less-trusted agents;
- do not treat a separate worktree, branch, HOME subdirectory, process env or
  model choice as a trust boundary.

## 4. Hard activation gate

All of the following must be independently verified before setting
`developer_isolation_verified = true` in any deployed configuration:

1. Operator broad PAT, personal SSH key and operator service credentials are
   absent from or inaccessible to the developer UID/HOME (existence and access
   checks only; never print or inspect values).
2. A separate scoped developer GitHub App/installation token can push only the
   assigned repository/branch and open a PR; it cannot merge, change settings,
   or reach other repositories.
3. Negative Kubernetes checks with the actual developer identity: no Secrets,
   no production namespaces, no write verbs, no other-Pod `pods/exec`.
4. The developer cannot invoke Operator credential, Argo sync, host exec,
   production write or break-glass capabilities, including through
   `workspace_exec`.
5. Audit shows role, tool, call id, bounded argument metadata and denial reason;
   no credential values are logged.
6. A disposable end-to-end worker launch, UI visibility, intervention,
   cancellation and own-PR flow is reviewed on the live environment.

Only then may a reviewed GitOps change set the gate. Source merge is not live
activation. The existing `workspace_enabled`/`developer_enabled` flags and the
new gate remain `false` in `yesvus/ops`.

## 5. Acceptance evidence in this change

`tests/test_integrations.py` covers:

- Developer role requires both enablement and the isolation gate;
- model/client/ACP-profile claims grant no role;
- break-glass requires separate activation and a fresh bounded expiry;
- break-glass does not inherit Operator capabilities;
- duplicate integrations, wildcards, missing targets and malformed tags fail
  closed;
- Developer can launch only the exact allowed repository/profile;
- Developer is denied credential apply, Argo sync, host exec and break-glass;
- Operator fixture writes are limited to the exact non-production target;
- disabled integrations are denied for every role;
- server-level discovery filtering, direct-call denial and audit reasons.

Run:

```sh
pytest -q tests/test_integrations.py
pytest -q
ruff check .
ruff format --check .
```

## 6. Not done / blockers for #23 LEG 3

- No live OpenHands worker was launched; live launch remains blocked by the
  shared HOME credential state and the #731 cutover.
- No credential was read, rotated or inspected; no token or live flag changed.
- No production, staging, Kubernetes or GitOps mutation, deployment or merge.
- The end-to-end UI/cancel/own-PR acceptance remains an owner-reviewed live
  milestone after identity/credential isolation, not a source claim.
