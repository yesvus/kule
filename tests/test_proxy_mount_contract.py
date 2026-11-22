"""Source-only compatibility proof for a maintained Kubernetes MCP backend.

This creates two *synthetic* in-memory MCP tools, not a Kubernetes connection.
Kule must explicitly tag only allowlisted proxy tools; everything else fails
closed at both tools/list and tools/call. Keep this test when upgrading FastMCP.
"""

import json

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server import create_proxy
from fastmcp.server.transforms import ToolTransform
from fastmcp.server.transforms.tool_transform import ToolTransformConfig

from kule.audit import AuditLog, verify
from kule.authz import Policy
from kule.middleware import OperatorMiddleware


async def test_proxy_mount_only_exposes_explicit_read_allowlist(tmp_path):
    backend = FastMCP("synthetic-upstream")

    @backend.tool()
    def pods_list() -> str:
        return "pods-read"

    @backend.tool()
    def pods_exec() -> str:
        return "forbidden"

    holder = {"claims": {"sub": "owner", "groups": ["ops"]}}
    policy = Policy(required_group="ops", exec_group="exec", exec_enabled=False)
    audit_path = tmp_path / "audit.jsonl"
    gateway = FastMCP(
        "kule-proxy-fixture",
        middleware=[
            OperatorMiddleware(
                policy=policy,
                audit=AuditLog(audit_path),
                kill_switch=tmp_path / "DISABLED",
                timeout_seconds=5,
                max_output_bytes=4096,
                claims_getter=lambda: holder["claims"],
            )
        ],
    )
    gateway.mount(create_proxy(backend), namespace="k8s")
    # Upstream Go MCP tool annotations are not Kule authorization tier tags.
    # Explicitly tag only the reviewed allowlisted tool.
    gateway.add_transform(ToolTransform({"k8s_pods_list": ToolTransformConfig(tags={"read"})}))

    async with Client(gateway) as client:
        names = {tool.name for tool in await client.list_tools()}
        assert names == {"k8s_pods_list"}
        result = await client.call_tool("k8s_pods_list", {})
        assert result.data == "pods-read"
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("k8s_pods_exec", {})

    holder["claims"] = {"sub": "outsider", "groups": []}
    async with Client(gateway) as client:
        assert await client.list_tools() == []
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("k8s_pods_list", {})

    assert verify(audit_path) == (True, 4)
    events = [json.loads(line)["event"] for line in audit_path.read_text().splitlines()]
    assert events == ["call", "result", "denied", "denied"]
