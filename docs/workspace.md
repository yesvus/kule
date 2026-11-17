# WS-KULE-WORKSPACE (#12) — standalone Karga Tezgah

**Status: source-only; OFF by default. No new live Kule RBAC, token mounts, or workspace tool enablement.**

## Current target (18 Nov 2026)

The Coder-managed `coder` workspace described in the original #14 source is retired from active service. The current standalone development workload is:

- Namespace/Deployment: `tezgah/tezgah`
- Observed Pod: `tezgah-7fd87c54-cr8dm`, on node `karga` (ephemeral name, **not** a permanent policy identifier)
- Container for bounded file/command tools: `ssh`, UID 10001, `/workspace`, `/usr/bin/python3` verified with a read-only toolchain check
- Persistent shared HOME: `tezgah/home` PVC; multiple agent containers share state. This is **one trust domain**, not a per-agent security sandbox.
- The old Coder workload/controller were scaled down during #1082, but retained recovery data must be handled by its owners.

This PR **only** updates Kule source and its contract to target the new namespace and container. Do not turn on the workspace flag using the old Coder Pod identity, even if a stale Pod reappears.

## Transport and scope

Reuse the digest-pinned `containers/kubernetes-mcp-server` binary with a separate, strictly scoped `pods_exec`-only projected ServiceAccount identity. No operator observer token, node SSH, cluster-admin kubeconfig, Docker socket, hostPath, root shell, or second public MCP endpoint.

The three typed Kule tools are:

- `workspace_exec(command)`: 8-second process deadline, bounded stdout/stderr, terminated child processes; arbitrary execution is **not** a credential sandbox.
- `workspace_read(path)`: UTF-8, maximum 8 KiB, under `/workspace`; no traversal, hidden files or symlinks.
- `workspace_write(path,text)`: maximum 8 KiB, existing parents and atomic replacement, same path restrictions.

Audit writes only bounded metadata: command UTF-8 byte count and SHA-256; file-path UTF-8 byte count and SHA-256; for file writes, text byte count and validity. **Neither raw commands nor file-write bodies are written to the audit trail.** Result payloads are bounded and redacted before return where applicable. This log discipline is independently tested in `tests/test_workspace.py`.

The proxy's underlying `pods_exec` call is not exposed as a callable Kule tool. The target is fixed at `namespace=tezgah`, `container=ssh`, `name=KULE_WORKSPACE_POD`; `KULE_WORKSPACE_POD` must equal the independently approved `KULE_WORKSPACE_APPROVED_POD`. Runtime validates the exact Tezgah Deployment Pod naming format, but **the actual authorization boundary is Kubernetes RBAC**, not the regex or a path guard.

Kule expects `KULE_WORKSPACE_API_URL` as a verified HTTPS Kubernetes API origin and separate projected token `/var/run/kule-workspace/token` and CA `/var/run/kule-workspace/ca.crt`, only inside the Kule Pod. The kubeconfig uses `tokenFile` and pins the `tezgah` context. This is NOT an invitation to copy credentials into Git or the developer Pod.

## Proposed independent GitOps RBAC (not applied)

The `resourceNames` value below is **illustrative** and must be revalidated from the then-live Deployment immediately before a reviewed rollout.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kule-workspace
  namespace: mcp-system
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kule-tezgah-exec
  namespace: tezgah
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  resourceNames: ["REPLACE_WITH_EXACT_LIVE_TEZGAH_POD_NAME"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kule-tezgah-exec
  namespace: tezgah
subjects:
- kind: ServiceAccount
  name: kule-workspace
  namespace: mcp-system
roleRef:
  kind: Role
  name: kule-tezgah-exec
  apiGroup: rbac.authorization.k8s.io
```

Do not grant `pods` list/watch, Kubernetes Secrets, production `pods/exec`, cross-namespace execution, deployment write or cluster-admin. The token must not be mounted into Tezgah agents. A normal Deployment rollout changes its Pod name and intentionally requires repinning this permission via GitOps, not dynamically selecting the first matching Pod.

## Authorization and security gates

- `[tools] workspace_enabled=false` remains the default. The `mcp-workspace` group is distinct from `mcp-gurbet-operators` and global exec; the current policy additionally requires the operator base group. The separate low-privilege OpenHands developer identity is **not implemented by this change** and is tracked in ops #1108.
- **P0: ops #731 credential isolation.** The new `tezgah/home` was migrated from the legacy Coder HOME. Verify that no broad personal GitHub PAT or personal SSH private key is accessible to UID 10001 before enabling remotely callable `workspace_exec`. If necessary, first switch to repo-scoped GitHub App tokens and remove only the developer-side legacy credential copies, never the Gurbet operator's credentials. Do not inspect or print token contents.
- Validate live `can-i` with the **actual projected** workspace token: yes for exactly the approved Pod's `pods/exec create`, no for other Pods/namespaces, Secrets and production workloads. Verify inherited ClusterRoleBindings do not expand rights.
- Review GitOps ServiceAccount/Role/RoleBinding, token/CA projection, DNS/NetworkPolicy, exact target Pod name and image digest separately. Preserve Kule's existing OAuth state and current deployed read-only observer until selective release approval.
- After isolation and authorization tests, use actual ChatGPT Kule calls to create/read/delete a disposable file, prove command cancellation/bounds, reject cross-boundary targets and confirm redacted audit metadata. Then update ops #378 SentinelX parity.
- Verify a separate trusted Tailscale SSH / OCI emergency path before any owner-authorized SentinelX shutdown.

**No live production or staging action, Tezgah filesystem mutation, Kule image promotion, or SentinelX cutover is implied by source merge.**


## Separate cheap developer identity (ops #1108 — source-only)

By default Kule requires `auth.required_group` (the existing operator group) for all roles. To avoid granting an inexpensive agent operator credentials simply to use Tezgah, Kule now supports a **separately gated developer workspace identity**; it does *not* grant Kubernetes observation, `note_write`, generic exec, Secret reads, Argo sync, or operator privileges.

Optional, **do not enable in the live operator gateway yet**:

```toml
[auth]
required_group = "mcp-gurbet-operators" # existing operator policy, unchanged
workspace_group = "mcp-workspace"       # distinct explicit workspace grant
developer_group = "mcp-developers"      # new developer identity

[tools]
workspace_enabled = false              # leave disabled until #731 and targeted Pod RBAC
developer_enabled = false              # extra gate for non-operator workspace access
```

Effective policy (both tool discovery and call-time authorization):

| Caller groups | Read/operate Kubernetes & notes | Workspace | Global exec |
| --- | --- | --- | --- |
| `mcp-gurbet-operators` | Existing operator grants | Requires `mcp-workspace` and `workspace_enabled` | Existing dedicated exec group plus opt-in |
| `mcp-developers` + `mcp-workspace`, no operator group | **No** | Only when **both** `workspace_enabled` and `developer_enabled` are true | **No** |
| `mcp-developers` alone | **No** | **No** | **No** |
| `mcp-workspace` alone | **No** | **No** | **No** |
| Unauthenticated/other | **No** | **No** | **No** |

This is a **source capability only**, not a provisioned machine OAuth client, Authentik group, JWT issuer, independent namespace ServiceAccount, or a secure worker sandbox. Full enablement is blocked by #731 (legacy broad GitHub PAT/personal SSH key in migrated shared HOME), and by review of Kule's exact-Pod Tezgah `pods/exec` identity, negative Kubernetes rights, and actual authenticated non-operator agent token behavior. Separate worker identities must be verified end to end; never assign cheap agents `mcp-gurbet-operators` as a workaround.

**Limit:** All Tezgah agents sharing UID 10001/HOME remain in the *same trust domain*. `workspace_exec` can read all files available to that UID. Git worktrees are concurrency organization, not permission isolation. For a stricter reader-only agent, use a separate backend/credential boundary rather than giving it a shell or relabeling unrestricted Kubernetes reads as observer-safe.

The feature flags **remain false** in `yesvus/ops` until the credential isolation and independent identity gates are accepted. This code change must not modify the live Kule OAuth DCR state or require SentinelX retirement.
