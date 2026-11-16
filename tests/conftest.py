from __future__ import annotations

from pathlib import Path

import pytest

from operator_mcp.config import AuditConfig, AuthConfig, Config, ServerConfig, ToolsConfig


@pytest.fixture
def make_cfg(tmp_path: Path):
    def _make(**tools) -> Config:
        return Config(
            server=ServerConfig(public_url="https://mcp.example.com", state_dir=tmp_path),
            auth=AuthConfig(
                oidc_config_url="https://id.example.com/.well-known/openid-configuration",
                client_id="client",
                required_group="ops",
                exec_group="ops-exec",
                client_secret="s",
                jwt_signing_key="k" * 40,
            ),
            audit=AuditConfig(path=tmp_path / "audit.jsonl"),
            tools=ToolsConfig(scratch_dir=tmp_path / "scratch", **tools),
        )

    return _make


class Claims:
    """Mutable claims holder standing in for the request's access token."""

    def __init__(self) -> None:
        self.value: dict | None = None

    def __call__(self) -> dict | None:
        return self.value


@pytest.fixture
def claims() -> Claims:
    return Claims()


OPERATOR = {"sub": "u1", "preferred_username": "owner", "groups": ["ops"]}
OUTSIDER = {"sub": "u2", "preferred_username": "guest", "groups": ["viewers"]}
