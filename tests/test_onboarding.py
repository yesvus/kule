"""First-run setup creates no credentials and diagnostics never print them."""

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
