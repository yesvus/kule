from pathlib import Path

import pytest

from operator_mcp.audit import AuditLog, verify
from operator_mcp.config import ConfigError, load_config
from operator_mcp.redact import MASK, redact, redact_text


def test_audit_chain_detects_edits(tmp_path: Path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(3):
        log.write("call", n=i)
    assert verify(p) == (True, 3)
    # A new writer continues the chain.
    AuditLog(p).write("call", n=3)
    assert verify(p) == (True, 4)
    lines = p.read_text().splitlines()
    lines[1] = lines[1].replace('"n": 1', '"n": 9')
    p.write_text("\n".join(lines) + "\n")
    assert verify(p) == (False, 2)


@pytest.mark.parametrize(
    "secret",
    [
        "ghp_" + "b" * 36,
        "sk-" + "c" * 40,
        "AKIA" + "D" * 16,
        "Bearer abcdefghijklmnop",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrst",
    ],
)
def test_redact_known_token_shapes(secret):
    assert secret not in redact_text(f"value {secret} end")


def test_redact_key_value_and_dict_keys():
    assert redact_text("password=hunter2") == f"password={MASK}"
    assert redact({"api_key": "x", "nested": {"token": "y"}, "ok": "z"}) == {
        "api_key": MASK,
        "nested": {"token": MASK},
        "ok": "z",
    }


GOOD = """
[server]
public_url = "https://mcp.example.com"
[auth]
oidc_config_url = "https://id.example.com/.well-known/openid-configuration"
client_id = "c"
"""

ENV = {"OPERATOR_MCP_OIDC_CLIENT_SECRET": "s", "OPERATOR_MCP_JWT_SIGNING_KEY": "k" * 32}


def write(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text)
    return p


def test_config_loads_with_env_secrets(tmp_path):
    cfg = load_config(write(tmp_path, GOOD), ENV)
    assert cfg.auth.client_secret == "s"
    assert "client_secret" not in repr(cfg.auth)


@pytest.mark.parametrize(
    ("extra", "env", "msg"),
    [
        ('[server]\nhost = "0.0.0.0"\n', ENV, "loopback"),
        ("", {}, "CLIENT_SECRET"),
        ("", {**ENV, "OPERATOR_MCP_JWT_SIGNING_KEY": "short"}, "32 characters"),
    ],
)
def test_config_rejects_unsafe_settings(tmp_path, extra, env, msg):
    text = GOOD.replace("[server]\n", "[server]\n" + extra.removeprefix("[server]\n"))
    with pytest.raises(ConfigError, match=msg):
        load_config(write(tmp_path, text), env)


def test_config_refuses_secrets_in_file(tmp_path):
    with pytest.raises(ConfigError, match="environment"):
        load_config(write(tmp_path, GOOD + 'client_secret = "x"\n'), ENV)


# --- review follow-ups -------------------------------------------------------


def test_audit_chain_detects_deleted_middle_line(tmp_path: Path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(4):
        log.write("call", n=i)
    lines = p.read_text().splitlines()
    del lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert verify(p) == (False, 1)


def test_audit_two_writers_share_one_chain(tmp_path: Path):
    p = tmp_path / "a.jsonl"
    a, b = AuditLog(p), AuditLog(p)
    a.write("call", n=1)
    b.write("call", n=2)
    a.write("call", n=3)
    assert verify(p) == (True, 3)


def test_audit_repairs_torn_tail(tmp_path: Path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).write("call", n=1)
    with p.open("a") as fh:
        fh.write('{"partial": tr')  # crash mid-write, no newline
    log = AuditLog(p)
    log.write("call", n=2)
    assert verify(p) == (True, 3)  # call, audit_repair, call
    assert '"audit_repair"' in p.read_text()


@pytest.mark.parametrize("bad", ["[]", "null", "1", '"x"'])
def test_verify_reports_non_object_lines(tmp_path: Path, bad):
    p = tmp_path / "a.jsonl"
    p.write_text(bad + "\n")
    assert verify(p) == (False, 0)


def test_verify_reports_invalid_utf8(tmp_path: Path):
    p = tmp_path / "a.jsonl"
    p.write_bytes(b"\xff\xfe\n")
    assert verify(p) == (False, 0)


@pytest.mark.parametrize(
    "text",
    [
        "DB_PASSWORD=hunter2",
        "OPENAI_API_KEY=abc123",
        "access_token=abc123",
        '{"password": "hunter2"}',
        "client_secret: abc123",
    ],
)
def test_redact_prefixed_and_json_keys(text):
    out = redact_text(text)
    assert "hunter2" not in out and "abc123" not in out
    assert MASK in out


def test_config_rejects_bad_port_and_groups_and_redirects(tmp_path):
    base = GOOD.replace("[server]\n", "[server]\nport = 70000\n")
    with pytest.raises(ConfigError, match="port"):
        load_config(write(tmp_path, base), ENV)
    same = GOOD + 'required_group = "ops"\nexec_group = "ops"\n'
    with pytest.raises(ConfigError, match="differ"):
        load_config(write(tmp_path, same), ENV)
    as_str = GOOD + 'allowed_client_redirect_uris = "https://chatgpt.com/x"\n'
    with pytest.raises(ConfigError, match="array"):
        load_config(write(tmp_path, as_str), ENV)


def test_cli_reports_errors_without_traceback(tmp_path, capsys):
    from operator_mcp.cli import main

    assert main(["audit-verify", str(tmp_path / "missing.jsonl")]) == 2
    bad = tmp_path / "bad.toml"
    bad.write_text("not = [valid")
    assert main(["check-config", "--config", str(bad)]) == 2
    assert "config error" in capsys.readouterr().err
