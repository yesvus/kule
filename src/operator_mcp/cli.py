"""Command line: `operator-mcp serve` and `operator-mcp audit-verify`."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .audit import verify
from .config import load_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="operator-mcp")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="run the MCP server (Streamable HTTP on loopback)")
    serve.add_argument("--config", type=Path, required=True)

    check = sub.add_parser("check-config", help="validate config and environment, then exit")
    check.add_argument("--config", type=Path, required=True)

    av = sub.add_parser("audit-verify", help="verify the audit log hash chain")
    av.add_argument("path", type=Path)

    args = parser.parse_args(argv)

    if args.cmd == "audit-verify":
        try:
            ok, count = verify(args.path)
        except OSError as exc:
            print(f"audit-verify error: {exc}", file=sys.stderr)
            return 2
        print(f"{'ok' if ok else 'BROKEN'}: {count} valid records")
        return 0 if ok else 1

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError) as exc:  # ConfigError, TOMLDecodeError
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "check-config":
        try:
            if os.environ.get("KULE_OPENHANDS_ENABLED") == "1":
                from .tools.openhands import validate_settings

                validate_settings()
        except RuntimeError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return 2
        print(f"config ok: {cfg.server.public_url} -> {cfg.server.host}:{cfg.server.port}")
        return 0

    from .server import build_auth, build_server

    mcp = build_server(cfg, auth=build_auth(cfg))
    mcp.run(transport="http", host=cfg.server.host, port=cfg.server.port, path="/mcp")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
