"""Build the FastMCP server with OIDC proxy auth and the operator middleware."""

from __future__ import annotations

import os
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from fastmcp.server.auth.oidc_proxy import OIDCProxy

from .audit import AuditLog
from .authz import Policy
from .config import Config
from .integrations import IntegrationRegistry
from .middleware import ClaimsGetter, OperatorMiddleware, claims_from_request
from .tools import (
    basic,
    host_exec,
    kubernetes,
    openhands,
    upstream_argocd,
    upstream_kubernetes,
    workspace,
)

INSTRUCTIONS = (
    "Operator tools for a self-hosted host. Every call is authorized against the "
    "caller's identity-provider groups and written to an audit log. Prefer read "
    "tools; ask the user before any tool that changes state."
)


class AuthentikRefreshOIDCProxy(OIDCProxy):
    """Preserve requested scopes while asking Authentik for a refresh token.

    FastMCP 4.2.0 forwards the client's scopes verbatim. ChatGPT currently
    requests only openid/profile, but Authentik requires offline_access for
    refresh token issuance. Add it upstream without dropping optional client
    scopes, and keep Kule's own group/tool authorization unchanged.
    """

    def _build_upstream_authorize_url(self, txn_id: str, transaction: dict[str, Any]) -> str:
        requested = transaction.get("scopes") or self.required_scopes or []
        scopes = list(dict.fromkeys([*requested, "offline_access"]))
        return super()._build_upstream_authorize_url(txn_id, {**transaction, "scopes": scopes})


def build_auth(cfg: Config) -> AuthProvider:
    # Keep FastMCP's encrypted OAuth state under our state directory.
    # Set unconditionally: an inherited value must not redirect or share it.
    os.environ["FASTMCP_HOME"] = str(cfg.server.state_dir / "fastmcp")
    return AuthentikRefreshOIDCProxy(
        config_url=cfg.auth.oidc_config_url,
        client_id=cfg.auth.client_id,
        client_secret=cfg.auth.client_secret,
        # Upstream (IdP) access tokens must be issued for our client.
        audience=cfg.auth.client_id,
        base_url=cfg.server.public_url,
        # `profile` carries the groups claim in authentik's default mappings.
        required_scopes=["openid", "profile"],
        valid_scopes=["openid", "profile", "email", "offline_access"],
        jwt_signing_key=cfg.auth.jwt_signing_key,
        allowed_client_redirect_uris=cfg.auth.allowed_client_redirect_uris,
        require_authorization_consent=True,
    )


def build_server(
    cfg: Config,
    *,
    auth: AuthProvider | None = None,
    claims_getter: ClaimsGetter = claims_from_request,
    integrations: IntegrationRegistry | None = None,
) -> FastMCP:
    policy = Policy(
        required_group=cfg.auth.required_group,
        exec_group=cfg.auth.exec_group,
        exec_enabled=cfg.tools.exec_enabled,
        groups_claim=cfg.auth.groups_claim,
        workspace_group=cfg.auth.workspace_group,
        workspace_enabled=cfg.tools.workspace_enabled,
        developer_group=cfg.auth.developer_group,
        developer_enabled=cfg.tools.developer_enabled,
        developer_isolation_verified=cfg.tools.developer_isolation_verified,
        breakglass_group=cfg.auth.breakglass_group,
        breakglass_enabled=cfg.tools.breakglass_enabled,
        breakglass_max_ttl_seconds=cfg.tools.breakglass_max_ttl_seconds,
    )
    audit = AuditLog(cfg.audit.path)
    middleware = OperatorMiddleware(
        policy=policy,
        audit=audit,
        kill_switch=cfg.kill_switch_path,
        timeout_seconds=cfg.tools.timeout_seconds,
        max_output_bytes=cfg.tools.max_output_bytes,
        claims_getter=claims_getter,
        integrations=integrations if integrations is not None else IntegrationRegistry(),
    )
    mcp = FastMCP(
        name="operator-mcp",
        instructions=INSTRUCTIONS,
        auth=auth,
        middleware=[middleware],
    )
    basic.register(mcp, cfg, claims_getter, policy)
    host_exec.register(mcp, cfg)
    workspace.register(mcp, cfg)
    kubernetes.register(mcp, timeout_seconds=cfg.tools.timeout_seconds)
    if os.environ.get("KULE_K8S_UPSTREAM_ENABLED") == "1":
        upstream_kubernetes.mount(mcp)
    if os.environ.get("KULE_ARGOCD_UPSTREAM_ENABLED") == "1":
        upstream_argocd.mount(mcp)
    if os.environ.get("KULE_OPENHANDS_ENABLED") == "1":
        openhands.mount(mcp, timeout_seconds=cfg.tools.timeout_seconds)
    return mcp
