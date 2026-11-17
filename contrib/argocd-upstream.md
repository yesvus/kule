# Optional Argo CD observer (Kule issue #11)

This source integration is **disabled by default**. It mounts
[argoproj-labs/mcp-for-argocd](https://github.com/argoproj-labs/mcp-for-argocd),
currently pinned to npm version **0.9.0**, as a local stdio child process
behind Kule's existing OAuth, group authorization, timeout/output cap,
kill-switch and tamper-evident audit middleware. No upstream HTTP port,
second connector, privileged host shell or Kubernetes admin credential.

## Exposed MCP tools

| Kule tool | Purpose |
| --- | --- |
| argocd_list_applications | List Argo Applications and their reported status |
| argocd_get_application | Inspect one Application's status, health and sync revision |
| argocd_get_application_resource_tree | Inspect managed-resource health/tree |
| argocd_get_application_events | Inspect an Application's events |

The upstream backend also implements generic manifests, logs, clusters,
AppProjects and mutation tools. They are **not tagged** and are hidden/denied
by Kule for this release. Its prompts/resources/templates are disabled.
Both upstream MCP_READ_ONLY and Kule's explicit read-tool allowlist are
required. All writes, including sync, are absent.

## Runtime contract (GitOps owner: yesvus/ops)

1. First use a **dedicated Argo CD observer identity** granted only
   application get/list (and required event/tree reads) on the approved
   AppProjects. No account with admin, deletion or sync authority. Argo
   read RBAC is the actual backend enforcement boundary; Kule groups gate
   callers. AppProject segmentation is tracked in ops#399.
2. ESO/OpenBao delivers one mounted JSON registry file at
   /var/run/kule-argocd/token-registry.json. It must have exactly one
   entry and a file mode that is not world-accessible (e.g. 0440, readable
   by uid 10001 via an appropriate fsGroup). No tokens in Git, TOML,
   GitHub Actions, logs or tool arguments:

       [{"baseUrl":"https://argocd.example.test","token":"<secret>"}]

   Set KULE_ARGOCD_BASE_URL to that **same** HTTPS origin. No paths, URLs
   supplied by users or extra registry destinations. The backend binds
   the registry token to its registered base URL; per-call URL override
   cannot route that token to an unregistered host.
3. Only after reviewing the Argo token's native RBAC and TLS/network
   connectivity, set KULE_ARGOCD_UPSTREAM_ENABLED=1 in the existing Kule
   Deployment. Do not expose the upstream container or a separate Service.
   Restrict Kule egress to the approved internal Argo endpoint. Use valid
   TLS; do not disable certificate verification.
4. Build both amd64 and arm64 in CI. Promote the verified **OCI digest**,
   never a mutable tag. Keep the existing Kule gateway URL and Authentik
   OAuth registration. Ensure read-only observers can actually call the
   four tools, and wrong-group/anonymous callers cannot discover or call
   them. Validate audit output without exposing credentials.

## Non-goals / required follow-up

- No live production sync, enablement or Argo RBAC changes in this PR.
- A production/staging sync path requires separate project-scoped
  identities, an explicit authorization request for the named Application
  and full pinned commit SHA, a forced prune=false default, and negative
  cross-project tests. Upstream read-only mode does **not** support
  permitting sync alone; never simply turn it off with an admin token.
- Native Argo status is not a full Git-vs-live diff. The four tools
  expose sync status and tree, not raw manifest content. Implement
  redacted diff separately if needed after verifying RBAC and safe output.
- OpenBao/ESO secret delivery, dedicated read-only Argo identity, ingress/
  egress restrictions and live end-to-end validation belong to ops#399
  and ops#461. SentinelX remains until operator parity plus an approved
  break-glass path have been demonstrated.

Synthetic authorization tests: tests/test_upstream_argocd.py.
