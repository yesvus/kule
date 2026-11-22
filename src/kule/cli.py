"""Kule server, onboarding, diagnostics, and audit commands."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .audit import verify
from .config import load_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kule")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="run the MCP server (Streamable HTTP on loopback)")
    serve.add_argument("--config", type=Path, required=True)

    check = sub.add_parser("check-config", help="validate config and environment, then exit")
    check.add_argument("--config", type=Path, required=True)

    init = sub.add_parser("init", help="create a private configuration for a new install")
    init.add_argument("--config", type=Path, default=Path("config.toml"))
    init.add_argument("--public-url", help="public HTTPS origin")
    init.add_argument("--oidc-config-url", help="OIDC discovery URL")
    init.add_argument("--client-id", help="registered OIDC client ID")
    init.add_argument("--required-group", default="kule-users")
    init.add_argument("--exec-group", default="kule-exec")

    doc = sub.add_parser("doctor", help="run read-only offline setup diagnostics")
    doc.add_argument("--config", type=Path, default=Path("config.toml"))

    av = sub.add_parser("audit-verify", help="verify the audit log hash chain")
    av.add_argument("path", type=Path)

    args = parser.parse_args(argv)

    if args.cmd == "init":
        from .onboarding import init_config

        try:
            init_config(
                args.config,
                public_url=args.public_url,
                oidc_config_url=args.oidc_config_url,
                client_id=args.client_id,
                required_group=args.required_group,
                exec_group=args.exec_group,
            )
        except (EOFError, KeyboardInterrupt):
            print("init cancelled", file=sys.stderr)
            return 130
        except (OSError, ValueError) as exc:
            print(f"init error: {exc}", file=sys.stderr)
            return 2
        print(f"Created {args.config} with private state, audit, and scratch directories.")
        print("Set KULE_OIDC_CLIENT_SECRET and a persistent KULE_JWT_SIGNING_KEY.")
        print(f"Next: kule doctor --config {args.config}")
        return 0

    if args.cmd == "doctor":
        from .onboarding import doctor

        return doctor(args.config)

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
