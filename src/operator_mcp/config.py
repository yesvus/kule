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


def load_config(path: Path, env: dict[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    with path.open("rb") as fh:
        data = tomllib.load(fh)

    s, a, au, t = (_section(data, n) for n in ("server", "auth", "audit", "tools"))
    for secret_key in SECRET_ENV:
        if secret_key in a:
            raise ConfigError(f"auth.{secret_key} must come from the environment, not the file")

    server = ServerConfig(
        host=s.get("host", "127.0.0.1"),
        port=int(s.get("port", 8795)),
        public_url=s.get("public_url", "").rstrip("/"),
        state_dir=Path(s.get("state_dir", "/var/lib/operator-mcp")),
    )
    auth = AuthConfig(
        oidc_config_url=a.get("oidc_config_url", ""),
        client_id=a.get("client_id", ""),
        required_group=a.get("required_group", "mcp-operators"),
        exec_group=a.get("exec_group", "mcp-exec"),
        groups_claim=a.get("groups_claim", "groups"),
        allowed_client_redirect_uris=list(
            a.get("allowed_client_redirect_uris", DEFAULT_ALLOWED_CLIENT_REDIRECTS)
        ),
        client_secret=env.get(SECRET_ENV["client_secret"], ""),
        jwt_signing_key=env.get(SECRET_ENV["jwt_signing_key"], ""),
    )
    audit = AuditConfig(path=Path(au.get("path", "/var/log/operator-mcp/audit.jsonl")))
    tools = ToolsConfig(
        exec_enabled=bool(t.get("exec_enabled", False)),
        scratch_dir=Path(t.get("scratch_dir", "/var/lib/operator-mcp/scratch")),
        timeout_seconds=float(t.get("timeout_seconds", 30.0)),
        max_output_bytes=int(t.get("max_output_bytes", 64 * 1024)),
    )
    cfg = Config(server=server, auth=auth, audit=audit, tools=tools)
    validate(cfg)
    return cfg


def validate(cfg: Config) -> None:
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
    if not cfg.auth.required_group:
        raise ConfigError("auth.required_group must not be empty")
    if not cfg.auth.allowed_client_redirect_uris:
        raise ConfigError("auth.allowed_client_redirect_uris must not be empty")
    if not 1 <= cfg.tools.timeout_seconds <= 110:
        raise ConfigError("tools.timeout_seconds must be between 1 and 110")
