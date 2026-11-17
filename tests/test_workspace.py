"""Source-only workspace tool tests. No cluster or developer secrets required."""
from __future__ import annotations

import json

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from operator_mcp.authz import WORKSPACE, Policy
from operator_mcp.server import build_server
from operator_mcp.tools import workspace, workspace_runner


POD = "coder-0267ee20-71a5-4b13-9917-bdf2a37c4c94-77895f6649-mxxv2"


def test_workspace_role_is_separate_from_global_exec():
    p = Policy(
        required_group="ops", exec_group="ops-exec", exec_enabled=False,
        workspace_group="ops-workspace", workspace_enabled=True,
    )
    workspace_operator = p.caller_from_claims({
        "sub": "owner", "groups": ["ops", "ops-workspace"],
    })
    assert p.allows(workspace_operator, {WORKSPACE})[0] is True
    assert p.allows(workspace_operator, {"exec"})[0] is False
    ordinary = p.caller_from_claims({"sub": "other", "groups": ["ops"]})
    assert p.allows(ordinary, {WORKSPACE})[0] is False
    assert p.allows(None, {WORKSPACE})[0] is False
    assert Policy("ops", "ops-exec", False).allows(workspace_operator, {WORKSPACE})[0] is False


def test_workspace_settings_are_off_by_default(make_cfg):
    cfg = make_cfg()
    assert cfg.tools.workspace_enabled is False


def test_runner_read_write_and_symlink_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(workspace_runner, "ROOT", tmp_path)
    (tmp_path / "src").mkdir()
    result = workspace_runner.run("write", {"path": "src/test.txt", "text": "hello"})
    assert result["written"] is True
    assert workspace_runner.run("read", {"path": "src/test.txt"})["text"] == "hello"
    assert (tmp_path / "src" / "test.txt").stat().st_mode & 0o777 == 0o600
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    (tmp_path / "src" / "target").symlink_to(outside / "t")
    for path in ("../outside", "/etc/passwd", ".config/gh/hosts.yml", "src/../t", "link/t"):
        with pytest.raises((ValueError, OSError)):
            workspace_runner.run("write", {"path": path, "text": "bad"})
    with pytest.raises((ValueError, OSError)):
        workspace_runner.run("read", {"path": "src/target"})
    assert not (outside / "t").exists()


def test_runner_exec_is_container_local_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(workspace_runner, "ROOT", tmp_path)
    result = workspace_runner.run("exec", {"command": "printf ok"})
    assert result["stdout"] == "ok"
    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    too_much = workspace_runner.run("exec", {"command": "head -c 10000 /dev/zero"})
    assert too_much["output_exceeded"] is True
    assert len(too_much["stdout"]) <= workspace_runner.MAX_BYTES
    monkeypatch.setattr(workspace_runner, "MAX_SECONDS", 0.15)
    timed = workspace_runner.run("exec", {"command": "sleep 5"})
    assert timed["timed_out"] is True


@pytest.mark.parametrize("bad", ["", "wrong", "coder-other-pod", "../coder-bad"])
def test_pod_pin_is_validated(monkeypatch, tmp_path, bad):
    token = tmp_path / "token"
    ca = tmp_path / "ca.crt"
    token.write_text("test")
    ca.write_text("fake")
    monkeypatch.setattr(workspace, "_TOKEN", token)
    monkeypatch.setattr(workspace, "_CA", ca)
    monkeypatch.setenv("KULE_WORKSPACE_API_URL", "https://127.0.0.1:6443")
    monkeypatch.setenv("KULE_WORKSPACE_POD", bad)
    with pytest.raises(RuntimeError):
        workspace._target()


async def test_mount_role_and_audit_do_not_leak_command_or_write_body(
    make_cfg, claims, monkeypatch, tmp_path
):
    token = tmp_path / "token"
    ca = tmp_path / "ca.crt"
    token.write_text("test-sa-only")
    ca.write_text("test-ca")
    monkeypatch.setattr(workspace, "_TOKEN", token)
    monkeypatch.setattr(workspace, "_CA", ca)
    monkeypatch.setattr(workspace, "_CONFIG", tmp_path / "kubeconfig")
    monkeypatch.setenv("KULE_WORKSPACE_API_URL", "https://127.0.0.1:6443")
    monkeypatch.setenv("KULE_WORKSPACE_POD", POD)

    requests = []

    async def fake_invoke(pod, operation, payload, timeout):
        requests.append((pod, operation, payload))
        if operation == "exec":
            return {"exit_code": 0, "stdout": "ok", "timed_out": False}
        if operation == "read":
            return {"path": payload["path"], "text": "sample"}
        return {"path": payload["path"], "bytes": len(payload["text"]), "written": True}

    monkeypatch.setattr(workspace, "_invoke", fake_invoke)
    cfg = make_cfg(workspace_enabled=True)
    mcp = build_server(cfg, claims_getter=claims)
    kubeconfig = json.loads((tmp_path / "kubeconfig").read_text())
    assert kubeconfig["users"][0]["user"]["tokenFile"] == str(token)
    assert "test-sa-only" not in (tmp_path / "kubeconfig").read_text()

    claims.value = {"sub": "viewer", "groups": ["ops"]}
    async with Client(mcp) as client:
        assert {t.name for t in await client.list_tools()} == {"whoami", "note_write"}
        with pytest.raises(ToolError):
            await client.call_tool("workspace_exec", {"command": "whoami"})

    claims.value = {"sub": "owner", "groups": ["ops", "mcp-workspace"]}
    async with Client(mcp) as client:
        names = {t.name for t in await client.list_tools()}
        assert {"workspace_exec", "workspace_read", "workspace_write"} <= names
        assert "workspace_exec" in names
        result = await client.call_tool("workspace_exec", {"command": "printf sensitive-value"})
        assert result.data["exit_code"] == 0
        await client.call_tool("workspace_write", {
            "path": "test.txt", "text": "credential-value-not-for-audit",
        })
        assert (await client.call_tool("workspace_read", {
            "path": "test.txt",
        })).data["text"] == "sample"

    assert all(record[0] == POD for record in requests)
    assert [record[1] for record in requests] == ["exec", "write", "read"]
    audit = cfg.audit.path.read_text()
    assert "credential-value-not-for-audit" not in audit
    assert "printf sensitive-value" not in audit
    assert "command_sha256" in audit


def test_workspace_upstream_config_only_exposes_pods_exec():
    import tomllib
    with open("contrib/kubernetes-workspace.toml", "rb") as stream:
        cfg = tomllib.load(stream)
    assert cfg["toolsets"] == ["core"]
    assert cfg["enabled_tools"] == ["pods_exec"]
    assert cfg["kubeconfig"] == "/tmp/kule-workspace-kubeconfig.json"
