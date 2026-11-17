# WS-KULE-WORKSPACE (#12) — Tezgah-only source contract

**Status: source-only; OFF by default. No live Kubernetes grants or Pod restart.**

The current runtime on 2026-11-17 is a **Coder-managed** workspace:
- namespace: `coder`
- workspace name: `tezgah`
- container: `dev` (UID 10001, cwd `/workspace`, Python 3 present)
- observed Pod: `coder-0267ee20-71a5-4b13-9917-bdf2a37c4c94-77895f6649-mxxv2`
- Coder's Deployment and PVC lifecycle must not be changed by Kule.
- The Karga storage migration is independently in progress; do not use an old
  hardcoded Pod name after a Coder stop/restart or migration.

## Transport and scope

Use the **digest-pinned upstream** `containers/kubernetes-mcp-server` binary and
its `pods_exec` tool behind Kule's existing authenticated MCP listener.
Do not publicly mount raw `pods_exec`. Kule's typed wrappers send only:
`namespace=coder`, the **pinned** `KULE_WORKSPACE_POD`, `container=dev`,
and `python3 -c <bounded runner>`. No host SSH, hostPath, host Docker
socket, cluster-admin kubeconfig or operator observer token is involved.

A separate projected Kubernetes ServiceAccount token at
`/var/run/kule-workspace/token` and cluster CA at
`/var/run/kule-workspace/ca.crt` must be mounted **only in the Kule Pod**.
The kubeconfig references `tokenFile`; token bytes are not copied.
`KULE_WORKSPACE_API_URL` must be a TLS-verified Kubernetes API origin.
`KULE_WORKSPACE_POD` must equal the separately reviewed
`KULE_WORKSPACE_APPROVED_POD`; the latter is the exact Pod name in the
namespace Role's `resourceNames`, not a general Coder name pattern.
The upstream config is `contrib/kubernetes-workspace.toml`.

The role design for an independent `yesvus/ops` PR is:

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
  namespace: coder
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  resourceNames:
  - "coder-0267ee20-71a5-4b13-9917-bdf2a37c4c94-77895f6649-mxxv2"
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kule-tezgah-exec
  namespace: coder
subjects:
- kind: ServiceAccount
  name: kule-workspace
  namespace: mcp-system
roleRef:
  kind: Role
  name: kule-tezgah-exec
  apiGroup: rbac.authorization.k8s.io
```

Kubernetes supports `resourceNames` on named subresources including
`pods/exec`, unlike top-level `create`. Source: official Kubernetes RBAC
reference. Do **not** add `pods` list/watch, `secrets`, `pods/log`,
any other named Pod, broad Pod execution, or cluster roles to this identity.
The GitOps application must keep manual/no-prune sync and independently
gate this new RoleBinding. Verify actual negative authorization on the
projected token (not `system:admin`) before enabling the flag.

## Authorization and controls

Set `[auth] workspace_group = "mcp-workspace"` (must differ from the
required and global exec groups) and `[tools] workspace_enabled = true`
only after scope tests. Kule still requires the ordinary operator group;
workspace users additionally need the distinct workspace group. The existing
global exec gate stays disabled. The same audit log, auth, kill switch and
middleware timeout apply. Command strings and written file contents are
**not** stored in audit logs. A command SHA-256 and byte count are logged.

Tools:
- `workspace_exec(command)`: run in `dev` as its existing UID with
  8-second process deadline, 8 KiB combined stdout/stderr bound,
  no interactive stdin, explicit exit code and Linux subreaper cleanup
  of remaining direct/detached child processes. Command return does not
  leave a deliberately backgrounded process running. This is not a
  hostile-code sandbox or a cgroup-level resource isolation guarantee.
- `workspace_read(path)`: UTF-8, max 8 KiB, existing regular files under
  `/workspace`, rejects absolute/hidden/traversal paths and symlinks.
- `workspace_write(path,text)`: max 8 KiB, existing parent directories
  only, atomic replacement, no absolute/hidden/traversal/symlink paths.

**Trust limitation:** `workspace_exec` is intentionally general-purpose
execution with **the existing developer UID**. It can access developer files
and any secrets available to that UID, regardless of the read/write wrappers'
path checks. Neither Authentik group checks nor Kubernetes RBAC can prevent
that. Ops #731 recorded a broad personal GitHub token and personal SSH
credential inside Tezgah; these **must be remediated** before enabling
workspace execution in a publicly reachable MCP gateway, or a differently
credentialed isolated workspace container/transport must be provided.
Only the *Kule's projected workspace identity* is denied Kubernetes Secret
API access. Commands in the existing Tezgah dev container may still use any
Kubernetes identity or credential mounted there; they are not isolated from
Tezgah-local secrets. Never describe it as a secure arbitrary shell.

## Acceptance and deployment gates

1. Source CI: role hiding, wrong-group denial, target validation,
   traversal/symlink negatives, process timeout and output bound, no audit
   content leakage, projected token reference rather than token copy.
2. After #731 credential remediation and Karga migration coordination:
   separate reviewed ops PR for the scoped ServiceAccount, RoleBinding,
   projected token, network policy and configuration. No other Kule roles
   or secrets changed.
3. With the dedicated **actual** token, prove
   `can-i create pods/exec -n coder --resource-name=<pinned Pod>` is yes;
   a different Pod in coder, a Pod in any other namespace,
   `get secrets`, and production Pod exec are **no**. Verify that
   no inherited ClusterRoleBinding adds privileges.
4. Check Tezgah is still the pinned running Coder Pod before rollout.
   A Pod replacement intentionally fails closed until GitOps is repinned.
5. Separate human-authorized ChatGPT calls: harmless temp file create,
   read, `workspace_exec` deletion, and negative path tests. Preserve
   Coder TUI, VS Code, PVC data and existing independent SSH recovery.
6. Only after full observed success update ops #378 parity checklist.
   Retire SentinelX in its own approved workstream; not here.
