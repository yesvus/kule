"""Configuration: non-secret settings from TOML, secrets from the environment."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# ChatGPT connector redirect URIs (OpenAI Apps SDK auth docs). Only these may
# be registered through dynamic client registration unless overridden.
DEFAULT_ALLOWED_CLIENT_REDIRECTS = [
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://chatgpt.com/connector/oauth/*",
]

SECRET_ENV = {
    "client_secret": "OPERATOR_MCP_OIDC_CLIENT_SECRET",
    "jwt_signing_key": "OPERATOR_MCP_JWT_SIGNING_KEY",
}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8795
    public_url: str = ""
    state_dir: Path = Path("/var/lib/operator-mcp")


@dataclass(frozen=True)
class AuthConfig:
    oidc_config_url: str = ""
    client_id: str = ""
    required_group: str = "mcp-operators"
    exec_group: str = "mcp-exec"
    groups_claim: str = "groups"
    allowed_client_redirect_uris: list[str] = field(
        default_factory=lambda: list(DEFAULT_ALLOWED_CLIENT_REDIRECTS)
    )
    client_secret: str = field(default="", repr=False)
    jwt_signing_key: str = field(default="", repr=False)


@dataclass(frozen=True)
class AuditConfig:
    path: Path = Path("/var/log/operator-mcp/audit.jsonl")


@dataclass(frozen=True)
class ToolsConfig:
    exec_enabled: bool = False
    scratch_dir: Path = Path("/var/lib/operator-mcp/scratch")
    timeout_seconds: float = 30.0
    max_output_bytes: int = 64 * 1024


@dataclass(frozen=True)
class Config:
    server: ServerConfig
    auth: AuthConfig
    audit: AuditConfig
    tools: ToolsConfig

    @property
    def kill_switch_path(self) -> Path:
        """If this file exists, every tool call is refused."""
        return self.server.state_dir / "DISABLED"


def _section(data: dict, name: str) -> dict:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a table")
    return value


def _str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    return value


def _int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} must be an integer (unquoted)")
    return value


def _float(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError(f"{name} must be a number (unquoted)")
    return float(value)


def _path(value: object, name: str) -> Path:
    text = _str(value, name)
    if not text.strip():
        raise ConfigError(f"{name} must not be empty")
    return Path(text)


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be true or false (unquoted)")
    return value


def _string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{name} must be an array of strings")
    return list(value)


def load_config(path: Path, env: dict[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    with path.open("rb") as fh:
        data = tomllib.load(fh)

    s, a, au, t = (_section(data, n) for n in ("server", "auth", "audit", "tools"))
    for secret_key in SECRET_ENV:
        if secret_key in a:
            raise ConfigError(f"auth.{secret_key} must come from the environment, not the file")

    server = ServerConfig(
        host=_str(s.get("host", "127.0.0.1"), "server.host"),
        port=_int(s.get("port", 8795), "server.port"),
        public_url=_str(s.get("public_url", ""), "server.public_url").rstrip("/"),
        state_dir=_path(s.get("state_dir", "/var/lib/operator-mcp"), "server.state_dir"),
    )
    auth = AuthConfig(
        oidc_config_url=_str(a.get("oidc_config_url", ""), "auth.oidc_config_url"),
        client_id=_str(a.get("client_id", ""), "auth.client_id"),
        required_group=_str(a.get("required_group", "mcp-operators"), "auth.required_group"),
        exec_group=_str(a.get("exec_group", "mcp-exec"), "auth.exec_group"),
        groups_claim=_str(a.get("groups_claim", "groups"), "auth.groups_claim"),
        allowed_client_redirect_uris=_string_list(
            a.get("allowed_client_redirect_uris", DEFAULT_ALLOWED_CLIENT_REDIRECTS),
            "auth.allowed_client_redirect_uris",
        ),
        client_secret=env.get(SECRET_ENV["client_secret"], ""),
        jwt_signing_key=env.get(SECRET_ENV["jwt_signing_key"], ""),
    )
    audit = AuditConfig(
        path=_path(au.get("path", "/var/log/operator-mcp/audit.jsonl"), "audit.path")
    )
    tools = ToolsConfig(
        exec_enabled=_bool(t.get("exec_enabled", False), "tools.exec_enabled"),
        scratch_dir=_path(
            t.get("scratch_dir", "/var/lib/operator-mcp/scratch"), "tools.scratch_dir"
        ),
        timeout_seconds=_float(t.get("timeout_seconds", 30.0), "tools.timeout_seconds"),
        max_output_bytes=_int(t.get("max_output_bytes", 64 * 1024), "tools.max_output_bytes"),
    )
    cfg = Config(server=server, auth=auth, audit=audit, tools=tools)
    validate(cfg)
    return cfg


def validate(cfg: Config) -> None:
    if not 1 <= cfg.server.port <= 65535:
        raise ConfigError("server.port must be between 1 and 65535")
    if cfg.server.host not in ("127.0.0.1", "::1", "localhost"):
        raise ConfigError("server.host must be loopback; publish through a reverse proxy")
    if not cfg.server.public_url.startswith("https://"):
        raise ConfigError("server.public_url must be an https:// URL")
    if not cfg.auth.oidc_config_url.startswith("https://"):
        raise ConfigError("auth.oidc_config_url must be an https:// URL")
    if not cfg.auth.client_id:
        raise ConfigError("auth.client_id is required")
    if not cfg.auth.client_secret:
        raise ConfigError(f"{SECRET_ENV['client_secret']} is not set")
    if len(cfg.auth.jwt_signing_key) < 32:
        raise ConfigError(f"{SECRET_ENV['jwt_signing_key']} must be at least 32 characters")
    if not cfg.auth.groups_claim:
        raise ConfigError("auth.groups_claim must not be empty")
    if not cfg.auth.required_group or not cfg.auth.exec_group:
        raise ConfigError("auth.required_group and auth.exec_group must not be empty")
    if cfg.auth.required_group == cfg.auth.exec_group:
        raise ConfigError("auth.exec_group must differ from auth.required_group")
    if not cfg.auth.allowed_client_redirect_uris:
        raise ConfigError("auth.allowed_client_redirect_uris must not be empty")
    if not 1 <= cfg.tools.timeout_seconds <= 110:
        raise ConfigError("tools.timeout_seconds must be between 1 and 110")
    if not 1024 <= cfg.tools.max_output_bytes <= 1024 * 1024:
        raise ConfigError("tools.max_output_bytes must be between 1024 and 1048576")
