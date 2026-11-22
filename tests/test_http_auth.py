"""Integration test of the real HTTP auth path, against a fake OIDC provider on loopback.

No network access beyond 127.0.0.1: the fake identity provider serves discovery and an
empty JWKS, which is enough for FastMCP's OIDC proxy to start and to reject bad tokens.
"""

from __future__ import annotations

import asyncio
import json
import multiprocessing
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx2
import pytest
from fastmcp import settings

from kule.server import build_auth, build_server

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


@pytest.fixture(autouse=True)
def isolated_fastmcp_settings(monkeypatch, tmp_path):
    # Deliberately start with a different import-time home. Restore the
    # singleton after each test; no OAuth state may leak between test cases.
    monkeypatch.setattr(settings, "home", tmp_path / "unrelated-home")
    monkeypatch.setenv("FASTMCP_HOME", str(tmp_path / "unrelated-home"))


@asynccontextmanager
async def running_app(
    make_cfg, oidc_url: str, monkeypatch, tmp_path, *, auth=None
) -> AsyncIterator:
    # Keep FastMCP's encrypted OAuth state inside the test's temporary directory.
    monkeypatch.setenv("FASTMCP_HOME", str(tmp_path / "fastmcp"))
    base = make_cfg()
    cfg = replace(base, auth=replace(base.auth, oidc_config_url=oidc_url))
    mcp = build_server(cfg, auth=auth if auth is not None else build_auth(cfg))
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


async def test_refresh_grant_registration_and_invalid_token_after_rebuild(
    make_cfg, oidc_discovery_url, monkeypatch, tmp_path
):
    """Exercise real token endpoint without contacting a production IdP.

    This proves refresh grant advertisement, client registration and rejection
    of an unknown refresh token across an app rebuild, not successful refresh
    of an issued token or persistence across a new process.
    """
    redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
    invalid_refresh = "synthetic-invalid-refresh-token"
    body = {
        **DCR_BODY,
        "grant_types": ["authorization_code", "refresh_token"],
        "redirect_uris": [redirect_uri],
    }
    async with running_app(make_cfg, oidc_discovery_url, monkeypatch, tmp_path) as client:
        metadata = await client.get("/.well-known/oauth-authorization-server")
        assert metadata.status_code == 200
        assert "refresh_token" in metadata.json()["grant_types_supported"]
        registration = await client.post("/register", json=body)
        assert registration.status_code in (200, 201)
        registered = registration.json()
        assert "refresh_token" in registered["grant_types"]
        form = {
            "grant_type": "refresh_token",
            "client_id": registered["client_id"],
            "refresh_token": invalid_refresh,
        }
        # Pinned FastMCP returns 401 for this invalid refresh grant.
        denied = await client.post("/token", data=form)
        assert denied.status_code == 401
        assert denied.json()["error"] == "invalid_grant"
        assert "access_token" not in denied.json()
        assert invalid_refresh not in denied.text

    # Reconstruct the real proxy with the same state path and signing key.
    # Do not re-register the client: a lost registration must fail this test.
    async with running_app(make_cfg, oidc_discovery_url, monkeypatch, tmp_path) as client:
        denied = await client.post("/token", data=form)
        assert denied.status_code == 401
        assert denied.json()["error"] == "invalid_grant"
        assert "access_token" not in denied.json()
        assert invalid_refresh not in denied.text
        # A never-registered client must fail at client authentication, not
        # be mistaken for a registered client with an invalid refresh grant.
        unknown_client = await client.post(
            "/token", data={**form, "client_id": "synthetic-unregistered-client"}
        )
        assert unknown_client.status_code == 401
        assert unknown_client.json()["error"] == "invalid_client"
        assert "access_token" not in unknown_client.json()
        assert invalid_refresh not in unknown_client.text
        unauthenticated = await client.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS)
        assert unauthenticated.status_code == 401


@pytest.mark.parametrize("fresh_process", [False, True], ids=["rebuild", "spawn"])
async def test_issued_refresh_rotates_after_proxy_rebuild(
    make_cfg, oidc_discovery_url, monkeypatch, tmp_path, fresh_process
):
    """Real proxy token exchanges; stub only upstream refresh transport.

    Seed synthetic callback state rather than simulating browser consent.
    The spawn case starts a fresh interpreter using the same disk state.
    Neither case verifies Authentik JWTs or actual ChatGPT link state.
    """
    import base64
    import hashlib
    import time

    from fastmcp.server.auth.oauth_proxy.models import ClientCode

    base = make_cfg()
    cfg = replace(base, auth=replace(base.auth, oidc_config_url=oidc_discovery_url))
    redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
    verifier = "v" * 43
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    scopes = ["openid", "profile"]
    initial_upstream = {
        "access_token": "synthetic-idp-access-1",
        "refresh_token": "synthetic-idp-refresh-1",
        "token_type": "Bearer",
        "expires_in": 600,
        "scope": "openid profile offline_access",
    }

    monkeypatch.setenv("FASTMCP_HOME", str(cfg.server.state_dir / "fastmcp"))
    proxy = build_auth(cfg)
    assert settings.home == cfg.server.state_dir / "fastmcp"
    assert (settings.home / "oauth-proxy").is_dir()
    assert not (tmp_path / "unrelated-home" / "oauth-proxy").exists()
    async with running_app(
        make_cfg, oidc_discovery_url, monkeypatch, tmp_path, auth=proxy
    ) as client:
        registered = await client.post(
            "/register",
            json={
                **DCR_BODY,
                "grant_types": ["authorization_code", "refresh_token"],
                "redirect_uris": [redirect_uri],
                "scope": "openid profile offline_access",
            },
        )
        assert registered.status_code in (200, 201)
        client_id = registered.json()["client_id"]
        # Mirror the callback record consumed by the pinned proxy (synthetic only).
        code = ClientCode(
            code="synthetic-callback-code",
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=challenge,
            code_challenge_method="S256",
            scopes=scopes,
            idp_tokens=initial_upstream,
            expires_at=time.time() + 300,
            created_at=time.time(),
        )
        await proxy._code_store.put(key=code.code, value=code)
        initial = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code": code.code,
                "code_verifier": verifier,
            },
        )
        assert initial.status_code == 200
        issued = initial.json()
        assert issued["refresh_token"] != initial_upstream["refresh_token"]
        assert issued["access_token"] != initial_upstream["access_token"]

    if fresh_process:
        # Spawn, not fork: no inherited Python cache, proxy or storage object.
        # Only synthetic OAuth data and the config cross the process boundary.
        process = multiprocessing.get_context("spawn").Process(
            target=_refresh_in_child, args=(cfg, initial_upstream, client_id, issued)
        )
        process.start()
        try:
            await asyncio.to_thread(process.join, 45)
            assert not process.is_alive(), "OAuth restart regression timed out"
            assert process.exitcode == 0, "fresh process could not rotate the token"
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)
            process.close()
    else:
        await _assert_refresh_rotation(cfg, initial_upstream, client_id, issued)


def _refresh_in_child(cfg, initial_upstream, client_id, issued):
    asyncio.run(_assert_refresh_rotation(cfg, initial_upstream, client_id, issued))


async def _assert_refresh_rotation(cfg, initial_upstream, client_id, issued):
    from unittest.mock import AsyncMock, patch

    rebuilt = build_auth(cfg)
    upstream = AsyncMock()
    upstream.refresh_token.side_effect = [
        {
            **initial_upstream,
            "access_token": "synthetic-idp-access-2",
            "refresh_token": "synthetic-idp-refresh-2",
        },
        {
            **initial_upstream,
            "access_token": "synthetic-idp-access-3",
            "refresh_token": "synthetic-idp-refresh-3",
        },
    ]

    @asynccontextmanager
    async def synthetic_upstream():
        yield upstream

    form = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": issued["refresh_token"],
    }
    app = build_server(cfg, auth=rebuilt).http_app(path="/mcp")
    transport = httpx2.ASGITransport(app=app)
    with patch.object(rebuilt, "_upstream_oauth_client", synthetic_upstream):
        async with (
            app.lifespan(app),
            httpx2.AsyncClient(transport=transport, base_url=PUBLIC_URL) as client,
        ):
            refreshed = await client.post("/token", data=form)
            assert refreshed.status_code == 200, (
                refreshed.status_code,
                refreshed.json().get("error"),
            )
            rotated = refreshed.json()
            assert rotated["access_token"] != issued["access_token"]
            assert rotated["refresh_token"] != issued["refresh_token"]
            assert rotated["refresh_token"] != "synthetic-idp-refresh-2"
            assert upstream.refresh_token.await_count == 1
            assert (
                upstream.refresh_token.await_args.kwargs["refresh_token"]
                == initial_upstream["refresh_token"]
            )

            replay = await client.post("/token", data=form)
            assert replay.status_code == 401
            assert replay.json()["error"] == "invalid_grant"
            assert "access_token" not in replay.json()
            assert upstream.refresh_token.await_count == 1

            # The new proxy refresh token must use the rotated upstream credential.
            again = await client.post(
                "/token", data={**form, "refresh_token": rotated["refresh_token"]}
            )
            assert again.status_code == 200
            assert upstream.refresh_token.await_count == 2
            assert (
                upstream.refresh_token.await_args.kwargs["refresh_token"]
                == "synthetic-idp-refresh-2"
            )
            assert again.json()["refresh_token"] != rotated["refresh_token"]
            assert again.json()["refresh_token"] != "synthetic-idp-refresh-3"


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
