"""Safe first-run configuration and offline setup diagnostics."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .config import ConfigError, load_config


def _required(value: str | None, flag: str, prompt: str) -> str:
    if value is None:
        if not sys.stdin.isatty():
            raise ConfigError(f"{flag} is required in non-interactive mode")
        value = input(f"{prompt}: ").strip()
    if not value or value != value.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ConfigError(f"{flag} must be a non-empty value without control characters")
    return value


def _https(value: str, flag: str, *, origin: bool = False) -> str:
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ConfigError(f"{flag} must be an HTTPS URL without whitespace")
    if "?" in value or "#" in value:
        raise ConfigError(f"{flag} must not include query or fragment delimiters")
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError:
        raise ConfigError(f"{flag} must be an HTTPS URL") from None
    if (
        url.scheme != "https"
        or not url.netloc
        or not url.hostname
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
        or (port is not None and not 1 <= port <= 65535)
        or (origin and url.path not in ("", "/"))
    ):
        raise ConfigError(f"{flag} must be an HTTPS {'origin' if origin else 'URL'}")
    normalized = "https://" + value.split("://", 1)[1]
    return normalized.rstrip("/") if origin else normalized


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ConfigError("setup directory must not be a symbolic link")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ConfigError("setup directory must be private (mode 0700)")


def init_config(
    path: Path,
    *,
    public_url: str | None,
    oidc_config_url: str | None,
    client_id: str | None,
    required_group: str,
    exec_group: str,
) -> None:
    """Create a private config for a new deployment without writing credentials."""
    if path.exists() or path.is_symlink():
        raise FileExistsError("configuration already exists; refusing to overwrite")
    if not path.parent.is_dir():
        raise ConfigError("configuration parent directory must already exist")

    public = _https(
        _required(public_url, "--public-url", "Public HTTPS origin"),
        "--public-url",
        origin=True,
    )
    oidc = _https(
        _required(oidc_config_url, "--oidc-config-url", "OIDC discovery URL"),
        "--oidc-config-url",
    )
    client = _required(client_id, "--client-id", "OIDC client ID")
    required_group = _required(required_group, "--required-group", "Required caller group")
    exec_group = _required(exec_group, "--exec-group", "Host execution group")
    if len({required_group, exec_group, "mcp-workspace", "mcp-developers"}) != 4:
        raise ConfigError("role groups must be distinct")

    local = path.absolute().parent / ".local"
    if local.is_symlink():
        raise ConfigError("setup ancestor .local must not be a symbolic link")
    root = local / "kule"
    directories = (local, root, root / "state", root / "audit", root / "scratch")
    for directory in directories:
        _private_directory(directory)

    def quote(value: str | Path) -> str:
        return json.dumps(str(value), ensure_ascii=False)

    content = (
        "# Kule configuration. OAuth secrets must come from the environment.\n"
        "# Back up the persistent state and keep the JWT signing key stable.\n\n"
        "[server]\n"
        'host = "127.0.0.1"\n'
        f"public_url = {quote(public)}\n"
        f"state_dir = {quote(root / 'state')}\n\n"
        "[auth]\n"
        f"oidc_config_url = {quote(oidc)}\n"
        f"client_id = {quote(client)}\n"
        f"required_group = {quote(required_group)}\n"
        f"exec_group = {quote(exec_group)}\n\n"
        "[audit]\n"
        f"path = {quote(root / 'audit' / 'audit.jsonl')}\n\n"
        "[tools]\n"
        f"scratch_dir = {quote(root / 'scratch')}\n"
        "exec_enabled = false\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def doctor(path: Path) -> int:
    """Read-only, offline preflight. Never display secret values or read SSH keys."""
    try:
        cfg = load_config(path)
    except (OSError, ValueError) as exc:
        print(f"FAIL config: {exc}", file=sys.stderr)
        return 2

    print("PASS configuration and secret presence")
    problems = 0
    for name, directory in (
        ("OAuth state", cfg.server.state_dir),
        ("audit", cfg.audit.path.parent),
        ("scratch", cfg.tools.scratch_dir),
    ):
        if directory.is_symlink() or not directory.is_dir():
            print(f"FAIL {name}: private writable directory missing or is a symlink")
            problems += 1
        elif stat.S_IMODE(directory.stat().st_mode) & 0o077 or not os.access(
            directory, os.W_OK | os.X_OK
        ):
            print(f"FAIL {name}: directory must be private and writable")
            problems += 1
        else:
            print(f"PASS {name} directory")

    if cfg.kill_switch_path.exists():
        print("FAIL emergency stop: DISABLED marker is present")
        problems += 1
    else:
        print("PASS emergency stop is not engaged")

    if cfg.tools.exec_enabled:
        from .tools.host_exec import _configured_target

        if cfg.tools.developer_enabled:
            print("FAIL host execution: developer runtime cannot share host shell")
            problems += 1
        if cfg.tools.timeout_seconds < 15:
            print("FAIL host execution: timeout must be at least 15 seconds")
            problems += 1
        if not Path("/usr/bin/ssh").is_file():
            print("FAIL host execution: SSH executable missing")
            problems += 1
        if os.environ.get("KULE_HOST_EXEC_ENABLED") != "1":
            print("FAIL host execution: enable gate missing")
            problems += 1
        try:
            _configured_target()
        except RuntimeError:
            print("FAIL host execution: fixed SSH target missing or invalid")
            problems += 1
        for name in ("id_ed25519", "known_hosts"):
            if not (Path("/var/run/kule-host-ssh") / name).is_file():
                print(f"FAIL host execution: SSH {name} file missing")
                problems += 1
    else:
        print("PASS privileged host execution disabled")

    # Validate the visible URL before printing it; legacy configs may be less strict.
    try:
        endpoint = urlsplit(cfg.server.public_url)
        port = endpoint.port
        safe_origin = (
            endpoint.scheme == "https"
            and endpoint.hostname is not None
            and (port is None or 1 <= port <= 65535)
            and endpoint.username is None
            and endpoint.password is None
            and endpoint.path in ("", "/")
            and not endpoint.query
            and not endpoint.fragment
            and "?" not in cfg.server.public_url
            and "#" not in cfg.server.public_url
            and all(
                not ch.isspace() and ord(ch) >= 32 and ord(ch) != 127
                for ch in cfg.server.public_url
            )
        )
    except ValueError:
        safe_origin = False
    if safe_origin:
        print(f"MCP endpoint: {cfg.server.public_url.rstrip('/')}/mcp")
    else:
        print("FAIL endpoint: public URL must be an HTTPS origin without credentials or query")
        problems += 1
    print("SKIP external HTTPS, OIDC connectivity, and client login (offline check)")
    return 1 if problems else 0
