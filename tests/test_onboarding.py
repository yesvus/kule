"""First-run setup creates no credentials and diagnostics never print them."""

import json
import stat
from pathlib import Path

import pytest

from kule.cli import main
from kule.config import load_config

ARGS = [
    "--public-url",
    "https://mcp.example.com",
    "--oidc-config-url",
    "https://id.example.com/.well-known/openid-configuration",
    "--client-id",
    "test-kule",
]


def snapshot_tree(root: Path) -> dict:
    result = {}
    for path in root.rglob("*"):
        st = path.lstat()
        result[path.relative_to(root)] = (
            stat.S_IMODE(st.st_mode),
            st.st_mtime_ns,
            path.read_bytes() if path.is_file() else None,
        )
    return result


@pytest.fixture(autouse=True)
def clear_legacy_secrets(monkeypatch):
    monkeypatch.delenv("OPERATOR_MCP_OIDC_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("OPERATOR_MCP_JWT_SIGNING_KEY", raising=False)


def initialize(tmp_path: Path) -> Path:
    config = tmp_path / "config.toml"
    assert main(["init", "--config", str(config), *ARGS]) == 0
    return config


def test_init_creates_private_valid_config_without_secrets(tmp_path):
    path = initialize(tmp_path)
    text = path.read_text()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "client_secret = " not in text
    assert "jwt_signing_key = " not in text
    root = tmp_path / ".local" / "kule"
    for item in (root, root / "state", root / "audit", root / "scratch"):
        assert item.is_dir()
        assert stat.S_IMODE(item.stat().st_mode) == 0o700

    cfg = load_config(
        path,
        {"KULE_OIDC_CLIENT_SECRET": "test-secret", "KULE_JWT_SIGNING_KEY": "x" * 48},
    )
    assert cfg.server.host == "127.0.0.1"
    assert cfg.server.public_url == "https://mcp.example.com"
    assert cfg.tools.exec_enabled is False
    assert cfg.server.state_dir == root / "state"
    assert cfg.auth.client_id == "test-kule"


def test_init_refuses_to_overwrite_existing_config(tmp_path, capsys):
    path = initialize(tmp_path)
    before = path.read_bytes()
    assert main(["init", "--config", str(path), *ARGS]) == 2
    assert path.read_bytes() == before
    assert "refusing to overwrite" in capsys.readouterr().err


@pytest.mark.parametrize(
    "url",
    [
        "http://mcp.example.com",
        "https://a.example/path",
        "https://a.example/?key=x",
        "https://a.example?",
        "https://a.example/#",
        "https://a.example#",
        "https://a.example/\x7f",
    ],
)
def test_init_rejects_unsafe_public_url(tmp_path, capsys, url):
    path = tmp_path / "config.toml"
    args = ["--public-url", url, *ARGS[2:]]
    assert main(["init", "--config", str(path), *args]) == 2
    assert not path.exists()
    assert "--public-url" in capsys.readouterr().err


def test_init_requires_flags_without_tty(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    path = tmp_path / "config.toml"
    assert main(["init", "--config", str(path)]) == 2
    assert "--public-url" in capsys.readouterr().err
    assert not path.exists()


def test_doctor_offline_is_read_only_and_redacts_secrets(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    capsys.readouterr()
    secret = "client-secret-must-stay-private"
    signing = "signing-key-must-stay-private" + "x" * 48
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", secret)
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", signing)
    before = snapshot_tree(tmp_path)
    assert main(["doctor", "--config", str(path)]) == 0
    stdout = capsys.readouterr().out
    after = snapshot_tree(tmp_path)
    assert before == after
    assert "PASS configuration" in stdout
    assert "SKIP external HTTPS" in stdout
    assert "https://mcp.example.com/mcp" in stdout
    assert secret not in stdout
    assert signing not in stdout


def test_doctor_detects_disabled_marker_without_changing_it(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)
    marker = tmp_path / ".local" / "kule" / "state" / "DISABLED"
    marker.touch()
    assert main(["doctor", "--config", str(path)]) == 1
    assert marker.exists()
    assert "FAIL emergency stop" in capsys.readouterr().out


def test_doctor_detects_missing_secret_without_echoing_values(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    monkeypatch.delenv("KULE_OIDC_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("OPERATOR_MCP_OIDC_CLIENT_SECRET", raising=False)
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)
    assert main(["doctor", "--config", str(path)]) == 2
    assert "KULE_OIDC_CLIENT_SECRET" in capsys.readouterr().err


def test_doctor_detects_missing_state_without_creating_it(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)
    state_dir = tmp_path / ".local" / "kule" / "state"
    state_dir.rmdir()
    assert main(["doctor", "--config", str(path)]) == 1
    assert not state_dir.exists()
    assert "FAIL OAuth state" in capsys.readouterr().out


def test_init_rejects_existing_symlink_to_config(tmp_path, capsys):
    original = tmp_path / "original.toml"
    original.write_text("do not replace")
    path = tmp_path / "config.toml"
    path.symlink_to(original)
    assert main(["init", "--config", str(path), *ARGS]) == 2
    assert original.read_text() == "do not replace"
    assert path.is_symlink()
    assert "refusing to overwrite" in capsys.readouterr().err


def test_init_rejects_group_collision(tmp_path, capsys):
    path = tmp_path / "config.toml"
    args = ["init", "--config", str(path), *ARGS, "--exec-group", "kule-users"]
    assert main(args) == 2
    assert "distinct" in capsys.readouterr().err
    assert not path.exists()


def test_doctor_never_echoes_embedded_url_credentials(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    text = path.read_text().replace(
        "https://mcp.example.com", "https://username:embedded-secret@mcp.example.com"
    )
    path.write_text(text)
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)
    assert main(["doctor", "--config", str(path)]) == 1
    output = capsys.readouterr().out
    assert "embedded-secret" not in output
    assert "FAIL endpoint" in output


@pytest.mark.parametrize("exception", [EOFError, KeyboardInterrupt])
def test_interactive_cancel_has_no_traceback(tmp_path, monkeypatch, capsys, exception):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    def interrupt(_prompt):
        raise exception()

    monkeypatch.setattr("builtins.input", interrupt)
    assert main(["init", "--config", str(tmp_path / "config.toml")]) == 130
    assert "init cancelled" in capsys.readouterr().err
    assert not (tmp_path / "config.toml").exists()


def test_init_normalizes_uppercase_scheme(tmp_path):
    path = tmp_path / "config.toml"
    args = [
        "--public-url",
        "HTTPS://mcp.example.com/",
        "--oidc-config-url",
        "HTTPS://id.example.com/.well-known/openid-configuration",
        "--client-id",
        "test-kule",
    ]
    assert main(["init", "--config", str(path), *args]) == 0
    cfg = load_config(
        path,
        {"KULE_OIDC_CLIENT_SECRET": "test-secret", "KULE_JWT_SIGNING_KEY": "x" * 48},
    )
    assert cfg.server.public_url == "https://mcp.example.com"
    assert cfg.auth.oidc_config_url.startswith("https://")


def test_init_rejects_symlinked_local_ancestor(tmp_path, capsys):
    external = tmp_path / "external"
    external.mkdir()
    (tmp_path / ".local").symlink_to(external, target_is_directory=True)
    path = tmp_path / "config.toml"
    assert main(["init", "--config", str(path), *ARGS]) == 2
    assert not (external / "kule").exists()
    assert not path.exists()
    assert "symbolic link" in capsys.readouterr().err


def test_doctor_fails_on_world_readable_state_directory(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)
    state_dir = tmp_path / ".local" / "kule" / "state"
    state_dir.chmod(0o755)
    assert main(["doctor", "--config", str(path)]) == 1
    assert "FAIL OAuth state" in capsys.readouterr().out
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o755


def test_doctor_checks_host_executor_prerequisites(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    path.write_text(
        path.read_text().replace(
            "exec_enabled = false", "exec_enabled = true\ntimeout_seconds = 10"
        )
    )
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)
    monkeypatch.delenv("KULE_HOST_EXEC_ENABLED", raising=False)
    monkeypatch.delenv("KULE_HOST_EXEC_TARGET", raising=False)
    assert main(["doctor", "--config", str(path)]) == 1
    output = capsys.readouterr().out
    assert "FAIL host execution: enable gate" in output
    assert "FAIL host execution: timeout" in output
    assert "FAIL host execution: fixed SSH target" in output
    assert "FAIL host execution: SSH id_ed25519" in output


def test_doctor_rejects_invalid_endpoint_port(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    path.write_text(
        path.read_text().replace("https://mcp.example.com", "https://mcp.example.com:99999")
    )
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)
    assert main(["doctor", "--config", str(path)]) == 1
    output = capsys.readouterr().out
    assert "99999" not in output
    assert "FAIL endpoint" in output


def test_init_accepts_existing_local_directory_mode_0755(tmp_path):
    local = tmp_path / ".local"
    local.mkdir(mode=0o755)
    local.chmod(0o755)
    path = initialize(tmp_path)
    assert path.exists()
    assert stat.S_IMODE(local.stat().st_mode) == 0o755
    for item in (local / "kule", local / "kule" / "state", local / "kule" / "audit"):
        assert stat.S_IMODE(item.stat().st_mode) == 0o700


def test_init_rejects_world_writable_local_ancestor(tmp_path, capsys):
    local = tmp_path / ".local"
    local.mkdir()
    local.chmod(0o777)
    path = tmp_path / "config.toml"
    assert main(["init", "--config", str(path), *ARGS]) == 2
    assert not path.exists()
    assert not (local / "kule").exists()
    assert "non-writable-by-others" in capsys.readouterr().err


def test_single_host_incompatible_integration_fails_doctor_and_check_config(
    tmp_path, monkeypatch, capsys
):
    path = initialize(tmp_path)
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)
    monkeypatch.setenv("KULE_SINGLE_HOST_IMAGE", "1")
    monkeypatch.setenv("KULE_K8S_API_URL", "https://localhost:6443")
    assert main(["doctor", "--config", str(path)]) == 2
    assert main(["check-config", "--config", str(path)]) == 2
    assert "Single-host Kule image" in capsys.readouterr().err


def _append_host_entry(
    config_path: Path,
    host_id: str,
    key_path: Path,
    known_hosts_path: Path,
    *,
    platform: str = "linux",
    host: str = "host.example.com",
    user: str = "operator",
    exec_enabled: bool = False,
    exec_groups: list[str] | None = None,
) -> None:
    groups = '["kule-exec"]' if exec_groups is None else json.dumps(exec_groups)
    config_path.write_text(
        config_path.read_text()
        + f"""
[[hosts]]
host_id = "{host_id}"
transport = "ssh"
platform = "{platform}"
description = "Test host {host_id}"
[hosts.ssh]
host = "{host}"
user = "{user}"
port = 22
key_path = "{key_path}"
known_hosts_path = "{known_hosts_path}"
[hosts.policy]
read_groups = ["kule-users"]
exec_groups = {groups}
exec_enabled = {"true" if exec_enabled else "false"}
"""
    )


def test_doctor_multi_host_valid_host_passes(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir(mode=0o700)
    key_path = ssh_dir / "id_ed25519"
    key_path.write_text("private-key-data")
    key_path.chmod(0o600)
    known_hosts_path = ssh_dir / "known_hosts"
    known_hosts_path.write_text("host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...")

    _append_host_entry(path, "zombie", key_path, known_hosts_path, platform="macos")
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)

    assert main(["doctor", "--config", str(path)]) == 0
    stdout = capsys.readouterr().out
    assert "PASS host zombie: SSH key and known_hosts" in stdout
    assert "PASS configuration" in stdout


def test_doctor_multi_host_missing_key_fails(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir(mode=0o700)
    key_path = ssh_dir / "nonexistent_key"
    known_hosts_path = ssh_dir / "known_hosts"
    known_hosts_path.write_text("host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...")

    _append_host_entry(path, "gurbet", key_path, known_hosts_path, platform="linux")
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)

    assert main(["doctor", "--config", str(path)]) == 1
    stdout = capsys.readouterr().out
    assert "FAIL host gurbet: SSH key file missing" in stdout


def test_doctor_multi_host_missing_known_hosts_fails(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir(mode=0o700)
    key_path = ssh_dir / "id_ed25519"
    key_path.write_text("private-key-data")
    key_path.chmod(0o600)
    known_hosts_path = ssh_dir / "nonexistent_known_hosts"

    _append_host_entry(path, "gurbet", key_path, known_hosts_path, platform="linux")
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)

    assert main(["doctor", "--config", str(path)]) == 1
    stdout = capsys.readouterr().out
    assert "FAIL host gurbet: SSH known_hosts file missing" in stdout


def test_doctor_multi_host_key_not_regular_file_fails(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir(mode=0o700)
    key_dir = ssh_dir / "id_directory"
    key_dir.mkdir(mode=0o700)
    known_hosts_path = ssh_dir / "known_hosts"
    known_hosts_path.write_text("host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...")

    _append_host_entry(path, "zombie", key_dir, known_hosts_path, platform="macos")
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)

    assert main(["doctor", "--config", str(path)]) == 1
    stdout = capsys.readouterr().out
    assert "FAIL host zombie: SSH key is not a regular file" in stdout


def test_doctor_multi_host_known_hosts_not_regular_file_fails(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir(mode=0o700)
    key_path = ssh_dir / "id_ed25519"
    key_path.write_text("private-key-data")
    key_path.chmod(0o600)
    known_hosts_dir = ssh_dir / "kh_directory"
    known_hosts_dir.mkdir(mode=0o700)

    _append_host_entry(path, "zombie", key_path, known_hosts_dir, platform="macos")
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)

    assert main(["doctor", "--config", str(path)]) == 1
    stdout = capsys.readouterr().out
    assert "FAIL host zombie: SSH known_hosts is not a regular file" in stdout


@pytest.mark.parametrize("mode", [0o644, 0o660, 0o640, 0o777, 0o604])
def test_doctor_multi_host_overly_permissive_key_mode_fails(tmp_path, monkeypatch, capsys, mode):
    path = initialize(tmp_path)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir(mode=0o700)
    key_path = ssh_dir / "id_ed25519"
    key_path.write_text("private-key-data")
    key_path.chmod(mode)
    known_hosts_path = ssh_dir / "known_hosts"
    known_hosts_path.write_text("host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...")

    _append_host_entry(path, "zombie", key_path, known_hosts_path, platform="macos")
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)

    assert main(["doctor", "--config", str(path)]) == 1
    stdout = capsys.readouterr().out
    assert "FAIL host zombie: SSH key must not be group- or world-readable" in stdout


def test_doctor_multi_host_no_secret_leakage(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir(mode=0o700)
    secret_key_body = "-----BEGIN OPENSSH PRIVATE KEY-----\nMYSUPERSECRETKEYMATERIAL\n-----END"
    key_path = ssh_dir / "id_ed25519_secret_token_12345"
    key_path.write_text(secret_key_body)
    key_path.chmod(0o644)  # Permissive on purpose to trigger failure
    known_hosts_path = ssh_dir / "known_hosts"
    known_hosts_path.write_text("sensitive-host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...")

    _append_host_entry(path, "zombie", key_path, known_hosts_path, platform="macos")
    secret_oidc = "oidc-super-secret-99999"
    secret_jwt = "jwt-signing-secret-" + "y" * 40
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", secret_oidc)
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", secret_jwt)

    assert main(["doctor", "--config", str(path)]) == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err

    assert "MYSUPERSECRETKEYMATERIAL" not in output
    assert "OPENSSH PRIVATE KEY" not in output
    assert secret_oidc not in output
    assert secret_jwt not in output
    assert "id_ed25519_secret_token_12345" not in output
    assert str(key_path) not in output
    assert str(known_hosts_path) not in output
    assert "FAIL host zombie: SSH key must not be group- or world-readable" in output


def test_doctor_multi_host_multiple_hosts_mixed_status(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir(mode=0o700)

    # Zombie is valid
    zombie_key = ssh_dir / "zombie_key"
    zombie_key.write_text("zombie-key")
    zombie_key.chmod(0o600)
    zombie_kh = ssh_dir / "zombie_kh"
    zombie_kh.write_text("zombie.lan ssh-ed25519 AAAA...")

    # Gurbet has missing key
    gurbet_key = ssh_dir / "nonexistent_gurbet_key"
    gurbet_kh = ssh_dir / "gurbet_kh"
    gurbet_kh.write_text("gurbet.internal ssh-ed25519 BBBB...")

    _append_host_entry(path, "zombie", zombie_key, zombie_kh, platform="macos")
    _append_host_entry(path, "gurbet", gurbet_key, gurbet_kh, platform="linux")

    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)

    assert main(["doctor", "--config", str(path)]) == 1
    stdout = capsys.readouterr().out
    assert "PASS host zombie: SSH key and known_hosts" in stdout
    assert "FAIL host gurbet: SSH key file missing" in stdout


def test_doctor_multi_host_symlink_key_fails(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir(mode=0o700)
    real_key = ssh_dir / "real_key"
    real_key.write_text("private-key-data")
    real_key.chmod(0o600)
    symlink_key = ssh_dir / "symlink_key"
    symlink_key.symlink_to(real_key)
    known_hosts_path = ssh_dir / "known_hosts"
    known_hosts_path.write_text("host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...")

    _append_host_entry(path, "zombie", symlink_key, known_hosts_path, platform="macos")
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)

    assert main(["doctor", "--config", str(path)]) == 1
    stdout = capsys.readouterr().out
    assert "FAIL host zombie: SSH key is not a regular file" in stdout


def test_doctor_multi_host_symlink_known_hosts_fails(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir(mode=0o700)
    key_path = ssh_dir / "id_ed25519"
    key_path.write_text("private-key-data")
    key_path.chmod(0o600)
    real_kh = ssh_dir / "real_known_hosts"
    real_kh.write_text("host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...")
    symlink_kh = ssh_dir / "symlink_known_hosts"
    symlink_kh.symlink_to(real_kh)

    _append_host_entry(path, "zombie", key_path, symlink_kh, platform="macos")
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)

    assert main(["doctor", "--config", str(path)]) == 1
    stdout = capsys.readouterr().out
    assert "FAIL host zombie: SSH known_hosts is not a regular file" in stdout


def test_doctor_multi_host_key_mode_000_fails(tmp_path, monkeypatch, capsys):
    path = initialize(tmp_path)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir(mode=0o700)
    key_path = ssh_dir / "id_ed25519"
    key_path.write_text("private-key-data")
    key_path.chmod(0o000)
    known_hosts_path = ssh_dir / "known_hosts"
    known_hosts_path.write_text("host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...")

    _append_host_entry(path, "zombie", key_path, known_hosts_path, platform="macos")
    monkeypatch.setenv("KULE_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("KULE_JWT_SIGNING_KEY", "x" * 48)

    assert main(["doctor", "--config", str(path)]) == 1
    stdout = capsys.readouterr().out
    assert "FAIL host zombie: SSH key must be readable by owner" in stdout
