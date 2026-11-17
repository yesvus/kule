# RFC 0001: Trust boundaries and MCP deployment topology for Kule

- **Status:** Proposed / Request for Comments — **not approved for implementation**
- **Date:** 2026-11-18
- **Project:** [yesvus/kule](https://github.com/yesvus/kule)
- **Related:** [Kule #18](https://github.com/yesvus/kule/issues/18), [ops #1108](https://github.com/yesvus/ops/issues/1108), [Kule PR #17](https://github.com/yesvus/kule/pull/17), [ops #731](https://github.com/yesvus/ops/issues/731), [ops #1023](https://github.com/yesvus/ops/issues/1023), [ops #1030](https://github.com/yesvus/ops/issues/1030)
- **Review requested from:** Independent architecture/security reviewer, including a frontier model such as Claude Opus

> This document is intentionally a **proposal**, not an architecture decision record (ADR).
> Reviewers should challenge the preferred design, complexity and assumptions.
> Do not create or enable infrastructure, change access, rotate secrets or merge implementation PRs merely because this RFC exists.

## 1. Context and constraints

Kule is a **personal self-hosted MCP gateway** through which the owner and autonomous agents operate Kubernetes, Argo CD, GitHub, OCI, the Tezgah development workspace, and approved credential workflows. The priority is to allow *trusted* agents substantial autonomous capability while restricting lower-confidence development agents, **not** to require human confirmation on every routine operator action.

The owner's proposed canonical roles are:

| Role | Intended capabilities | Expected caller |
| --- | --- | --- |
| **Developer** | Tezgah worktrees, code/tests, PRs, bounded read-only observability; no credential provisioning or production mutations | Less-trusted/inexpensive developer agents |
| **Operator** | Broad but scoped operational tools: production/staging deploy, Kubernetes/Argo CD, GitHub/OCI, credential issuance/delivery via private executor; normal authorized writes autonomous | Explicitly trusted agent or owner |
| **Break-glass** | Emergency/root/recovery, high-impact IAM/RBAC, master issuer bootstrap, exceptional destructive actions; time-limited and independently activated | Owner or explicitly authorized emergency agent |

Trust is **assigned to an authenticated agent/session identity**. Model name, price, purported intelligence or prompting cannot grant permission. These are *three role names*, not three mandatory replicas.

The goal is a clean codebase (KISS), one shared source/image, opt-in integrations and reuse of maintained upstream MCP servers. No new custom IAM engine, dynamic plugin marketplace, per-agent VM, new credential controller or public administrative endpoint without demonstrated need.

### Existing verified repository state (as of this RFC)

- Kule is FastMCP with Authentik-backed OIDCProxy, an `OperatorMiddleware` handling tool-list filtering/call authorization/audit, and `read/operate/exec/workspace` tags; these are **not yet the three-role enforcement model**. In current source `read` and `operate` share the base required group. See [authz.py](../../src/operator_mcp/authz.py), [middleware.py](../../src/operator_mcp/middleware.py), [server.py](../../src/operator_mcp/server.py).
- Existing GitOps deployment is `mcp-system/operator-mcp` on Gurbet with `https://mcp.yesvus.com/mcp`, a dedicated service account and projected read-only Kubernetes identity, plus an externally reachable OAuth/MCP ingress. See [ops deployment](https://github.com/yesvus/ops/blob/main/cluster/operator-mcp-pilot/deployment.yaml) and [route](https://github.com/yesvus/ops/blob/main/cluster/operator-mcp-pilot/public-route.yaml). **Preserve the working endpoint/OAuth connection**.
- Kule already mounts maintained Kubernetes and Argo CD MCP implementations behind its own gateway selectively. Newly deployed upstream tools have experienced client discovery gaps ([#16](https://github.com/yesvus/kule/issues/16)); there has also been an OAuth reconnect issue ([#5](https://github.com/yesvus/kule/issues/5)).
- [PR #17](https://github.com/yesvus/kule/pull/17) is **open, source-only** and adds default-disabled independent developer-group groundwork. It does **not** deploy or prove a separate developer trust boundary.
- The shared Tezgah workspace on Karga uses git worktrees for collaboration. A worktree is **not a security sandbox**: shared UID, HOME, env, process and file permissions imply a shared trust domain. Developer PAT/SSH key exposure remediation in [ops #731](https://github.com/yesvus/ops/issues/731) remains a prerequisite for remote agent shell access.
- [ops credential issuer contract](https://github.com/yesvus/ops/blob/main/docs/secrets/ISSUER_CONTRACT.md) separates high-impact private issuer/executor from OpenBao escrow and delivery through ESO/GitHub encrypted environment APIs. Kule must orchestrate *typed* requests, never move raw provider master tokens through MCP.

## 2. Problem statement

We need a simple mechanism to give developer agents safe access and trusted operator agents useful, autonomous, high-impact access, without creating a vulnerability where a less-trusted agent can inherit the owner's broad credentials.

Questions:
1. Should roles/groups live in Authentik, Kule configuration, or both?
2. Should Kule run as **one policy-filtered MCP process**, **two isolated deployments** (Developer/Operator), or **three permanently running deployments** (including Admin)?
3. How do tool discovery, OAuth audience/claims, machine-to-machine authentication and backend privilege boundaries work across ChatGPT, OpenHands, OpenCode and Claude?
4. What is a practical break-glass mechanism that also works when Authentik/Kule is broken?
5. How do we preserve autonomy for an Operator while limiting irreversible blast radius?

## 3. Security invariants (proposed, independent of topology)

1. **Authentik authenticates principals and manages group/role assignment** (including machine/service identities). Kule enforces per-tool, per-action and per-target policy at **discovery and invocation**, while the underlying system enforces effective resource permissions. Do not build another account/group database in Kule.
2. A **low-trust agent never receives a high-trust token, filesystem mount, inherited environment, service account or direct network route**. Hiding tools or changing model names alone provides no security.
3. **Operator writes are normally autonomous** when explicitly authorized for a capability and target; no blanket `ask for approval on every write`. Separate a small set of high-blast-radius / irreversible operations.
4. **Secrets are not MCP data.** Provider master keys, OpenBao bootstrap/root and raw issued tokens must not appear in tool results, prompts, arguments, audit fields, CI/Git, errors or logs. Operator calls a scoped, short-lived **private trusted executor** that issues and delivers values without exposing them.
5. Backend permissions and network policy are defense in depth. Test **negative permissions** on K8s, GitHub, OpenBao and Argo CD; do not rely on application policy alone.
6. **No privilege escalation by selecting a different URL/tool label or model.** Developer JWT/tokens cannot authorize Operator endpoints; a caller must possess independently granted Operator identity. Resource/audience and issuer validation are mandatory; no token passthrough.
7. Break-glass activation requires a separate credential/process and must not rely exclusively on Authentik/Kule availability. TTL, audit, revocation and a viable out-of-band recovery path are mandatory.
8. One repo/image is preferable; do not share privileged credential mounts or Authentik OAuth state between differently trusted running instances.

## 4. Alternatives for review

| Option | Design | Advantages | Costs / risks |
| --- | --- | --- | --- |
| **A — Single Kule** | One server/process/Pod with strong per-session policy and multiple backend identities | Least operational overhead, simplest client UX, one endpoint | All backend credentials often coexist in same process/trust domain; bug/RCE can defeat logical roles; difficult to prove isolation for Developer |
| **B — Two runtimes, one codebase (tentative preference)** | Separate Developer and Operator deployments with distinct SA, secret mounts, network policy and OAuth client/audience/state; one image and shared modules; no permanent privileged Admin | Real backend isolation, keeps existing Operator endpoint, constrained Developer can be internal-only | Additional Pod/config/OAuth testing; potential client connection friction; duplicated runtime memory |
| **C — Three permanent runtimes** | Developer, Operator, Admin public/private server deployments | Explicit role-to-server mapping and strong deployment isolation if actually configured | Standing privileged Admin attack surface, resource waste, more credentials and OAuth/discovery failure cases; outage coupling |

**Tentative preference: B**, conditional on measurements and a demonstrated threat boundary. The RFC explicitly invites reviewers to choose **A** if isolation can be achieved without privileged backend credentials in the same trust domain, or a better option with **less** machinery.

### Proposed topology for option B

```text
                     Authentik (identity + groups / app policies)
                          |                         |
             restricted agent/session       trusted agent/owner
                          |                         |
                  Kule Developer              Kule Operator
                 internal/private            mcp.yesvus.com/mcp
                 distinct OAuth audience     existing OAuth continuity
                  restricted K8s SA           scoped operator K8s SA
                  repo-scoped GitHub App      Argo/GitHub/OCI scoped auth
                  no issuer key mounts        typed credential requests
                          |                         |
                  Tezgah / repo                private on-demand executor
                  readonly status                  |
                                              Provider ↔ OpenBao
                                                   |
                                           ESO / encrypted GH API

          BREAK-GLASS: separately activated, time-bound recovery privilege;
          preserve independent OCI/SSH/OpenBao access outside this diagram.
```

**Important:** Drawing two boxes or using two DNS names does *not* create isolation unless pods truly hold separate credentials, service identities, networking and storage. An Authentik human belonging to `kule-operators` should not make every agent launched under their UI session an Operator.

## 5. Proposed responsibility split

### Authentik — identity plane

- Candidate groups: `kule-developers`, `kule-operators`, `kule-breakglass`.
- Per-agent/client/service account identities where supported; application/provider bindings and claims are **audience-specific**.
- Explicit grant/revoke/change process, short-lived tokens as appropriate, credential lifecycle managed through Authentik/native provider features.
- **Open question:** which currently deployed Authentik/FastMCP flow supports OpenHands/OpenCode machine-to-machine sessions and ChatGPT simultaneously without token-sharing? Confirm through a disposable proof, not assumptions about DCR or client-credentials.
- **Open question:** groups vs Authentik application entitlements for authorization signals. Prefer simple groups first unless scope becomes cumbersome.

### Kule — capability plane

- Modest modular server: `core/` for auth/policy/audit/tool registry, `integrations/` for Kubernetes, Argo CD, workspace, credentials, etc. Avoid a plugin SDK until needed.
- Policy `principal + role + capability + target`; fixed namespace/repo/action allowlists, per-request checks and bounded outputs. No generic user-supplied shell/provider URL/secret path as an Operator shortcut.
- Developer and Operator can share same image and feature registrations **but not effective backend permissions**.
- For credential actions: `credential_profiles_list`, `credential_status`, `credential_plan`, optionally `credential_apply` through an approved private executor. Return metadata and correlation ID only.
- Explicit denial tests and audit logs; secrets never printed even to privileged models.

### Backend — enforcement plane

- Kubernetes separate ServiceAccounts/RoleBindings and (where relevant) namespaces and NetworkPolicies; audit exact allowed verbs/resources. Avoid mounting a cluster-admin kubeconfig.
- GitHub developer uses repo-scoped installation token; production/admin/workflow access withheld. No broad personal PAT/SSH key in shared Tezgah HOME.
- Argo CD application/project-scoped tokens; production sync/delete/prune policies independent from tool-name filters.
- OpenBao provider issuer identities **not mounted** in Kule. The private executor consumes reviewed per-consumer profiles, obtains scoped machine auth and writes directly to OpenBao; ESO/GitHub delivery owned by ops workstreams.
- Operator and break-glass should not share a root credential by default.

## 6. Threat model to challenge

- **Prompt injection / malicious repo issue or PR text:** Developer attempts to invoke privileged tools, change a policy file, or ask an Operator agent to mint keys. Does model-level delegation accidentally transfer Operator credentials?
- **Shared Tezgah shell:** Developer reaches a shared `~/.config/gh`, SSH key, process env, alternate checkout or service-account token despite worktree restriction.
- **Compromised Developer Pod:** Can it reach Operator service / API, use a stolen OAuth credential, or impersonate another caller?
- **Token confusion:** A Developer token for one client/resource is accepted at Operator's MCP endpoint, or ChatGPT's delegated user token is reused by all subagents.
- **FastMCP/upstream mounting changes:** New upstream tool appears after version bump; discovery hides it but invocation still works (or vice versa).
- **Privileged Operator misuse:** A powerful model autonomously performs erroneous production prune/secret rotation, including through a generic `workspace_exec` escape hatch.
- **Break-glass deadlock:** Authentik, DNS, OpenBao or Kule is down when root/recovery access is needed.
- **Issuer compromise / data exfiltration:** Master tokens leak to model/audit via tool results, errors or provider API retry logs.
- **Multi-node resources:** Developer on Karga and Operator on Gurbet share a control plane; prevent privilege pivot across namespaces while keeping operational overhead low.

## 7. Tradeoffs and non-goals

- **Security vs autonomy:** Delegate broad *routine* operator rights via explicit identity; exceptions should be few, well defined and revocable. A high model capability does not eliminate errors or prompt injection.
- **Separation vs capacity:** A second Kule Pod costs memory/CPU and maintenance. Before adoption, measure incremental memory, CPU and OAuth reliability, and ask whether single-runtime plus safer capability delegation suffices.
- **App auth vs runtime auth:** Authentik groups determine admission but K8s/issuer resource permissions remain authoritative. Separate MCP servers are an implementation technique, not a substitute for identity and scope checks.
- **Isolation vs convenience:** Developer worktrees are intentionally lightweight, not security boundaries. No VM per task as a default. If untrusted arbitrary code is executed, document the actual trust domain and limits.
- **Break-glass UX:** Do not create a 24/7 `kule-admin` service simply for naming symmetry. Consider temporary owner-managed identity/short-lived one-shot admin job, preserving out-of-band recovery.
- **No dynamic plugin marketplace**, redundant secret store, general IAM/reconciliation daemon, automatic credential exports, or wholesale replacement of functional upstream MCP services.

## 8. Proposed rollout gates (nothing here is authorized by this RFC)

1. **Design approval:** independent review with an explicit alternative recommendation and threat model; reconcile Kule #18 and ops #1108. Record accepted decision later as an ADR.
2. **Source-only capability matrix:** refactor authz minimally, add strict target checks, preserve current Operator/OAuth. Determine whether PR #17 can be used without merging an incompatible interim authorization policy.
3. **Identity proof:** synthetic Authentik service identity with distinct audience and role; verify denial of cross-endpoint tokens, group changes/revocation, refresh and client tool discovery. Do not change the working ChatGPT connection.
4. **Developer proof:** separate restricted service identity/SA/network, no Operator secret mounts, complete ops #731 credential cleanup, test one disposable Tezgah worktree, direct forbidden tool calls and negative K8s/GitHub/OpenBao/Argo tests.
5. **Operator proof:** trusted agent executes a safe *synthetic/nonproduction* authorized write autonomously, with metadata-only response, audit and rollback; no blanket per-call manual approval.
6. **Break-glass proof:** documented short-lived elevation, automatic expiry, revoke, out-of-band recovery when Authentik or Kule is offline; no permanent public root-level MCP.
7. **GitOps rollout only after separate approval:** immutable images, manual/no-prune resource-selected sync, exact-source CI/review, observe rollback and the existing Kule #5/#16 issues. Do not treat source merge as live activation.

## 9. Review questions for Claude Opus / independent reviewer

Please **critique, not endorse** the preference. Explicitly answer:

1. What is the **minimum** deployment isolation that prevents a low-trust Developer agent from using Operator secrets, including when tools execute arbitrary commands? Is two Kule Pods a meaningful trust boundary given shared cluster/node/UID possibilities?
2. Are **Authentik groups, application entitlements, separate providers, or a different pattern** best for user sessions vs agent machine identities? How do we avoid granting operator authority to all subagents of one logged-in human?
3. What is the correct **OAuth resource/audience and token-validation design** for current FastMCP OIDCProxy and clients? Can two Kule deployments safely share an Authentik issuer without accidentally accepting each other's tokens? What exact tests prove it?
4. Is the **two-runtime** proposal justified over a single FastMCP gateway with a restricted backend worker? What failure modes does it introduce, and what is a simpler alternative?
5. How would you implement **time-limited break-glass** so that recovery does not depend on the very Authentik/OpenBao/Kule components that may be failing? Should break-glass be an MCP at all?
6. Is it safe to let a trusted Operator autonomously invoke production and credential-delivery tools? Which narrowly defined actions genuinely need extra approval or two-person control?
7. Where should the **credential control plane** reside (Kule facade vs private executor)? How can issuance and delivery be idempotent with ambiguous provider/API outcomes and without value exposure?
8. How should we handle **tool-list drift** and upstream MCP upgrades, given current OAuth reconnect and tool discovery issues?
9. What threats or accidental complexity are we missing? Identify **one design you would reject outright** and why.
10. Give a concrete **minimal viable architecture**, a deny-test matrix and a staged migration plan that preserves today's working `mcp.yesvus.com/mcp`.

### Requested review format

- **Verdict:** Accept / Accept with changes / Reject (and why).
- **P0 flaws** (security, privilege bypass, recovery failure), with proof or specific reproduction.
- **Unnecessary complexity** to remove.
- **Recommended architecture** with trust boundaries and minimal components.
- **Decision table** comparing A, B, C (or D) with practical operational consequences.
- **Exact follow-up changes** to this RFC, plus a concise implementation/test checklist.
- Separate **confirmed findings** from assumptions requiring inspection.

## 10. Reference documentation

- Authentik [OAuth2 provider](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/), [application bindings](https://docs.goauthentik.io/add-secure-apps/applications/manage_apps/), [service accounts](https://docs.goauthentik.io/users-sources/user/account-types/service-accounts/), [M2M authentication](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/machine_to_machine/).
- MCP [authorization documentation](https://modelcontextprotocol.io/specification/draft/basic/authorization) and resource/audience validation.
- Internal source and issue links above are references to implementation **state**, not approval to deploy.
