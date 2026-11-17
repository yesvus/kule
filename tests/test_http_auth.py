"""Integration test of the real HTTP auth path, against a fake OIDC provider on loopback.

No network access beyond 127.0.0.1: the fake identity provider serves discovery and an
empty JWKS, which is enough for FastMCP's OIDC proxy to start and to reject bad tokens.
"""

from __future__ import annotations

import json
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx2
import pytest

from operator_mcp.server import build_auth, build_server

PUBLIC_URL = "https://mcp.example.com"
MCP_HEADERS = {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "probe", "version": "0"},
    },
}


class _Discovery(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep test output quiet
        pass

    def do_GET(self) -> None:
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        if self.path == "/.well-known/openid-configuration":
            body = {
                "issuer": base,
                "authorization_endpoint": f"{base}/authorize",
                "token_endpoint": f"{base}/token",
                "jwks_uri": f"{base}/jwks",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "code_challenge_methods_supported": ["S256"],
            }
        elif self.path == "/jwks":
            body = {"keys": []}
        else:
            self.send_error(404)
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture(scope="module")
def oidc_discovery_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Discovery)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/.well-known/openid-configuration"
    finally:
        server.shutdown()
        server.server_close()


@asynccontextmanager
async def running_app(make_cfg, oidc_url: str, monkeypatch, tmp_path) -> AsyncIterator:
    # Keep FastMCP's encrypted OAuth state inside the test's temporary directory.
    monkeypatch.setenv("FASTMCP_HOME", str(tmp_path / "fastmcp"))
    base = make_cfg()
    cfg = replace(base, auth=replace(base.auth, oidc_config_url=oidc_url))
    mcp = build_server(cfg, auth=build_auth(cfg))
    app = mcp.http_app(path="/mcp")
    async with app.lifespan(app):
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url=PUBLIC_URL) as client:
            yield client


async def test_mcp_endpoint_requires_bearer_token(
    make_cfg, oidc_discovery_url, monkeypatch, tmp_path
):
    async with running_app(make_cfg, oidc_discovery_url, monkeypatch, tmp_path) as client:
        resp = await client.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS)
    assert resp.status_code == 401
    challenge = resp.headers["www-authenticate"]
    assert "resource_metadata=" in challenge
    assert "/.well-known/oauth-protected-resource" in challenge


async def test_protected_resource_metadata(make_cfg, oidc_discovery_url, monkeypatch, tmp_path):
    async with running_app(make_cfg, oidc_discovery_url, monkeypatch, tmp_path) as client:
        resp = await client.get("/.well-known/oauth-protected-resource/mcp")
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"] == f"{PUBLIC_URL}/mcp"
    assert [s.rstrip("/") for s in body["authorization_servers"]] == [PUBLIC_URL]


async def test_authorization_server_metadata(make_cfg, oidc_discovery_url, monkeypatch, tmp_path):
    async with running_app(make_cfg, oidc_discovery_url, monkeypatch, tmp_path) as client:
        resp = await client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    body = resp.json()
    assert body["registration_endpoint"].startswith(f"{PUBLIC_URL}/")
    assert "S256" in body["code_challenge_methods_supported"]


DCR_BODY = {
    "client_name": "probe",
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
}


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://evil.example/cb",
        "https://chatgpt.com.evil.example/connector/oauth/x",
        "https://evil.example/?u=https://chatgpt.com/connector/oauth/x",
        "https://claude.ai.evil.example/api/mcp/auth_callback",
        "https://claude.ai/api/mcp/auth_callback.evil",
        "http://claude.ai/api/mcp/auth_callback",
        "http://chatgpt.com/connector_platform_oauth_redirect",
        "https://chatgpt.com/other/path",
    ],
)
async def test_registration_rejects_arbitrary_redirect_uri(
    make_cfg, oidc_discovery_url, monkeypatch, tmp_path, redirect_uri
):
    body = {**DCR_BODY, "redirect_uris": [redirect_uri]}
    async with running_app(make_cfg, oidc_discovery_url, monkeypatch, tmp_path) as client:
        resp = await client.post("/register", json=body)
    assert resp.status_code == 400
    body = resp.json()
    assert body.get("error") == "invalid_redirect_uri"
    assert "client_id" not in body


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://chatgpt.com/connector/oauth/example",
        "https://claude.ai/api/mcp/auth_callback",
    ],
)
async def test_registration_accepts_chatgpt_redirect_uri(
    make_cfg, oidc_discovery_url, monkeypatch, tmp_path, redirect_uri
):
    body = {**DCR_BODY, "redirect_uris": [redirect_uri]}
    async with running_app(make_cfg, oidc_discovery_url, monkeypatch, tmp_path) as client:
        resp = await client.post("/register", json=body)
    assert resp.status_code in (200, 201)
    assert resp.json()["client_id"]


async def test_garbage_bearer_token_is_rejected(
    make_cfg, oidc_discovery_url, monkeypatch, tmp_path
):
    headers = {**MCP_HEADERS, "authorization": "Bearer garbage"}
    async with running_app(make_cfg, oidc_discovery_url, monkeypatch, tmp_path) as client:
        resp = await client.post("/mcp", json=INITIALIZE, headers=headers)
    assert resp.status_code == 401


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        (["openid", "profile"], "openid profile offline_access"),
        (["openid", "profile", "email"], "openid profile email offline_access"),
        (["openid", "profile", "offline_access"], "openid profile offline_access"),
    ],
)
def test_upstream_refresh_scope_preserves_client_scopes(
    make_cfg, oidc_discovery_url, requested, expected
):
    """Only add offline_access upstream; retain all client-requested scopes."""
    from urllib.parse import parse_qs, urlsplit

    cfg = make_cfg()
    cfg = replace(cfg, auth=replace(cfg.auth, oidc_config_url=oidc_discovery_url))
    proxy = build_auth(cfg)
    # Only the local synthetic IdP is contacted. No real login or bearer.
    url = proxy._build_upstream_authorize_url("synthetic-transaction", {"scopes": requested})
    params = parse_qs(urlsplit(url).query)
    assert params["scope"] == [expected]
    assert params["response_type"] == ["code"]
    assert params["redirect_uri"] == [f"{PUBLIC_URL}/auth/callback"]
    assert proxy.required_scopes == ["openid", "profile"]
