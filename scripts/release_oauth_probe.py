#!/usr/bin/env python3
"""Read-only OAuth release probe against a disposable, external HTTPS Kule install.

Never print authorization codes, tokens, identity claims or request/response bodies.
This script does not create an IdP, change server configuration, or restart Kule.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
import webbrowser
from urllib.parse import urlsplit

import httpx2
from fastmcp import Client
from fastmcp.client.auth import OAuth
from fastmcp.exceptions import ToolError

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "kule-release-probe", "version": "0"},
    },
}
HEADERS = {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
}


def endpoint_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/mcp"
        or not parsed.netloc
    ):
        raise argparse.ArgumentTypeError("endpoint must be an HTTPS URL ending in /mcp")
    try:
        port = parsed.port
    except ValueError:
        raise argparse.ArgumentTypeError("invalid endpoint port") from None
    if port is not None and not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("invalid endpoint port")
    return value


async def check_anonymous(endpoint: str) -> None:
    """Reject uncredentialed MCP requests and verify protected-resource metadata."""
    origin = endpoint.removesuffix("/mcp")
    async with httpx2.AsyncClient(timeout=15.0) as http:
        response = await http.post(endpoint, headers=HEADERS, json=INITIALIZE)
        if response.status_code != 401:
            raise RuntimeError("unauthenticated MCP request was not rejected with 401")
        metadata = await http.get(f"{origin}/.well-known/oauth-protected-resource/mcp")
        if metadata.status_code != 200 or metadata.json().get("resource") != endpoint:
            raise RuntimeError("protected resource metadata is invalid")
    print("PASS anonymous denial and MCP OAuth resource metadata")


async def connected_whoami(endpoint: str, oauth: OAuth, *, expected_tools: bool) -> None:
    async with Client(endpoint, auth=oauth) as client:
        names = {tool.name for tool in await client.list_tools()}
        if expected_tools:
            if names != {"whoami", "note_write"}:
                raise RuntimeError("single-host tool set is unexpected")
            result = await client.call_tool("whoami", {})
            data = result.data
            if not isinstance(data, dict) or not data.get("user"):
                raise RuntimeError("authorized whoami did not return a caller")
        else:
            if names:
                raise RuntimeError("wrong-group caller can discover tools")
            try:
                await client.call_tool("whoami", {})
            except ToolError:
                pass
            else:
                raise RuntimeError("wrong-group caller can execute whoami")


async def check_stopped(endpoint: str, oauth: OAuth) -> None:
    async with Client(endpoint, auth=oauth) as client:
        try:
            await client.call_tool("whoami", {})
        except ToolError as exc:
            if "kill switch" not in str(exc).lower():
                raise RuntimeError("whoami denial was not attributed to emergency stop") from None
        else:
            raise RuntimeError("emergency stop failed to block whoami")


async def check_expiry(endpoint: str, oauth: OAuth, max_wait: int) -> None:
    context = oauth.context
    current = context.current_tokens
    expiry = context.token_expiry_time
    if current is None or not current.access_token or not isinstance(expiry, int | float):
        raise RuntimeError("client has no measurable token expiry")
    before = current.access_token
    delay = max(0.0, expiry - time.time() + 5)
    if delay > max_wait:
        raise RuntimeError("IdP token TTL exceeds configured acceptance wait; shorten test TTL")
    print(f"INFO waiting {int(delay) + 1} seconds until token expiry (no tokens printed)")
    await asyncio.sleep(delay)
    await connected_whoami(endpoint, oauth, expected_tools=True)
    after = oauth.context.current_tokens
    if after is None or after.access_token == before:
        raise RuntimeError("no access token rotation was observed after expiry")
    print("PASS refresh after access-token expiry without a second browser login")


async def run(args: argparse.Namespace) -> None:
    await check_anonymous(args.endpoint)
    if args.mode == "anonymous":
        return

    # The OAuth local redirect must be explicitly allowlisted on the disposable
    # server, not added to Kule's secure production defaults.
    oauth = OAuth(
        scopes=["openid", "profile"],
        callback_host="127.0.0.1",
        callback_port=args.callback_port,
        callback_timeout=300,
    )
    if args.mode == "wrong-group":
        print("INFO sign in with the disposable account lacking the required group")
        await connected_whoami(args.endpoint, oauth, expected_tools=False)
        print("PASS wrong-group tools hidden and whoami denied")
        return

    print("INFO sign in with the disposable account in the required group")
    if args.mode == "stopped":
        # The caller must engage DISABLED on the disposable server beforehand.
        await check_stopped(args.endpoint, oauth)
        print("PASS authenticated request denied by emergency stop")
        return

    await connected_whoami(args.endpoint, oauth, expected_tools=True)
    print("PASS OAuth login, authorized whoami, and default-disabled host execution")

    if args.restart:
        input(
            "Restart only the disposable Kule service preserving its state and key; press Enter: "
        )
        # An unexpected browser login on reconnect must fail the acceptance check.
        webbrowser.open = _unexpected_browser
        await connected_whoami(args.endpoint, oauth, expected_tools=True)
        print("PASS post-restart whoami without reauthentication")

    if args.refresh:
        # This prevents a silently fresh browser login from looking like refresh.
        webbrowser.open = _unexpected_browser
        await check_expiry(args.endpoint, oauth, args.max_expiry_wait)


def _unexpected_browser(*_args: object, **_kwargs: object) -> bool:
    raise RuntimeError("unexpected browser login; no silent reauthentication allowed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, type=endpoint_url)
    parser.add_argument(
        "--mode", choices=["anonymous", "authorized", "wrong-group", "stopped"],
        default="anonymous",
    )
    parser.add_argument("--callback-port", type=int, default=8765)
    parser.add_argument("--restart", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--max-expiry-wait", type=int, default=600)
    args = parser.parse_args()
    if not 1024 <= args.callback_port <= 65535 or args.max_expiry_wait < 1:
        parser.error("invalid callback port or expiry-wait bound")
    if (args.restart or args.refresh) and args.mode != "authorized":
        parser.error("--restart and --refresh require --mode authorized")
    try:
        asyncio.run(run(args))
    except (Exception, KeyboardInterrupt):
        # Never echo HTTP error payloads, tokens, claims, callback URLs or traceback.
        print(
            "FAIL release OAuth acceptance probe (details intentionally redacted)",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
