"""Build the FastMCP server with OIDC proxy auth and the operator middleware."""

from __future__ import annotations

import os

from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider

from .audit import AuditLog
from .authz import Policy
from .config import Config
from .middleware import ClaimsGetter, OperatorMiddleware, claims_from_request
from .tools import basic, kubernetes

INSTRUCTIONS = (
    "Operator tools for a self-hosted host. Every call is authorized against the "
    "caller's identity-provider groups and written to an audit log. Prefer read "
    "tools; ask the user before any tool that changes state."
)


def build_auth(cfg: Config) -> AuthProvider:
    from fastmcp.server.auth.oidc_proxy import OIDCProxy

    # Keep FastMCP's encrypted OAuth state under our state directory.
    # Set unconditionally: an inherited value must not redirect or share it.
    os.environ["FASTMCP_HOME"] = str(cfg.server.state_dir / "fastmcp")
    return OIDCProxy(
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
) -> FastMCP:
    policy = Policy(
        required_group=cfg.auth.required_group,
        exec_group=cfg.auth.exec_group,
        exec_enabled=cfg.tools.exec_enabled,
        groups_claim=cfg.auth.groups_claim,
    )
    audit = AuditLog(cfg.audit.path)
    middleware = OperatorMiddleware(
        policy=policy,
        audit=audit,
        kill_switch=cfg.kill_switch_path,
        timeout_seconds=cfg.tools.timeout_seconds,
        max_output_bytes=cfg.tools.max_output_bytes,
        claims_getter=claims_getter,
    )
    mcp = FastMCP(
        name="operator-mcp",
        instructions=INSTRUCTIONS,
        auth=auth,
        middleware=[middleware],
    )
    basic.register(mcp, cfg, claims_getter, policy)
    kubernetes.register(mcp, timeout_seconds=cfg.tools.timeout_seconds)
    return mcp
