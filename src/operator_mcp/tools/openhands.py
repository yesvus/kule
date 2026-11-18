"""Opt-in OpenHands Agent Canvas management adapter behind Kule's gateway.

OpenHands 1.62.0 exposes an MCP *client*, not a maintained MCP server for its
management REST API. Import the pinned OpenAPI schema with FastMCP instead of
hand-writing endpoint wrappers, then reduce it to an explicit endpoint and
request-field allowlist.

This is a management plane only. Agent tool execution, bash, files, secrets,
profiles, settings, plugins and the separate Automation Service API are not
mounted. The caller's OAuth group authorizes the tier; the target guard here
rejects workspace paths outside the configured Canvas source root.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import posixpath
import re
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx2
from fastmcp import FastMCP
from fastmcp.exceptions import AuthorizationError
from fastmcp.server.middleware import Middleware
from fastmcp.server.providers.openapi import MCPType

from ..authz import OPERATE, READ

_SPEC = Path(__file__).resolve().parent.parent / "openapi" / "openhands-1.62.0.json"
_SPEC_VERSION = "1.62.0"
_DEFAULT_WORKSPACE_ROOT = "/workspace/src"
_API_KEY_HEADER = "X-Session-API-Key"
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$")
_BRANCH_PREFIX = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._/-]{0,200})?$")
_TAG_KEY = re.compile(r"^[a-z0-9]{1,64}$")
_MAX_MESSAGE_BLOCKS = 32
_MAX_MESSAGE_BYTES = 32 * 1024
_MAX_MESSAGE_TOTAL_BYTES = 64 * 1024


@dataclass(frozen=True)
class _Endpoint:
    tool: str
    tier: str
    method: str
    path: str
    params: frozenset[str] = frozenset()


# Explicit allowlist keyed by the pinned upstream operationId. New upstream
# operations stay invisible until reviewed here.
_ENDPOINTS: dict[str, _Endpoint] = {
    "search_conversations_api_conversations_search_get": _Endpoint(
        "list_conversations",
        READ,
        "get",
        "/api/conversations/search",
        frozenset({"page_id", "limit", "status", "sort_order"}),
    ),
    "count_conversations_api_conversations_count_get": _Endpoint(
        "count_conversations",
        READ,
        "get",
        "/api/conversations/count",
        frozenset({"status"}),
    ),
    "get_conversation_api_conversations__conversation_id__get": _Endpoint(
        "get_conversation",
        READ,
        "get",
        "/api/conversations/{conversation_id}",
        frozenset({"conversation_id"}),
    ),
    "get_local_conversation_runtime_api_conversations__conversation_id__runtime_get": _Endpoint(
        "get_conversation_runtime",
        READ,
        "get",
        "/api/conversations/{conversation_id}/runtime",
        frozenset({"conversation_id"}),
    ),
    "search_conversation_events_api_conversations__conversation_id__events_search_get": _Endpoint(
        "search_events",
        READ,
        "get",
        "/api/conversations/{conversation_id}/events/search",
        frozenset(
            {
                "conversation_id",
                "page_id",
                "limit",
                "kind",
                "source",
                "body",
                "sort_order",
                "timestamp__gte",
                "timestamp__lt",
            }
        ),
    ),
    "get_conversation_event_api_conversations__conversation_id__events__event_id__get": _Endpoint(
        "get_event",
        READ,
        "get",
        "/api/conversations/{conversation_id}/events/{event_id}",
        frozenset({"conversation_id", "event_id"}),
    ),
    "list_agent_profiles_api_agent_profiles_get": _Endpoint(
        "list_agent_profiles",
        READ,
        "get",
        "/api/agent-profiles",
    ),
    "start_conversation_api_conversations_post": _Endpoint(
        "start_conversation",
        OPERATE,
        "post",
        "/api/conversations",
    ),
    "send_message_api_conversations__conversation_id__events_post": _Endpoint(
        "send_message",
        OPERATE,
        "post",
        "/api/conversations/{conversation_id}/events",
        frozenset({"conversation_id"}),
    ),
    "run_conversation_api_conversations__conversation_id__run_post": _Endpoint(
        "run_conversation",
        OPERATE,
        "post",
        "/api/conversations/{conversation_id}/run",
        frozenset({"conversation_id"}),
    ),
    "interrupt_conversation_api_conversations__conversation_id__interrupt_post": _Endpoint(
        "interrupt_conversation",
        OPERATE,
        "post",
        "/api/conversations/{conversation_id}/interrupt",
        frozenset({"conversation_id"}),
    ),
    "pause_conversation_api_conversations__conversation_id__pause_post": _Endpoint(
        "pause_conversation",
        OPERATE,
        "post",
        "/api/conversations/{conversation_id}/pause",
        frozenset({"conversation_id"}),
    ),
    "switch_conversation_acp_model_api_conversations__conversation_id__switch_acp_model_post": (
        _Endpoint(
            "switch_acp_model",
            OPERATE,
            "post",
            "/api/conversations/{conversation_id}/switch_acp_model",
            frozenset({"conversation_id"}),
        )
    ),
}

_START_FIELDS = frozenset(
    {
        "workspace",
        "worktree",
        "worktree_options",
        "initial_message",
        "agent_profile_id",
        "max_iterations",
        "max_budget_per_run",
        "tags",
        "autotitle",
    }
)
_AUDIT_FIELDS = frozenset(
    {
        "conversation_id",
        "event_id",
        "limit",
        "page_id",
        "status",
        "sort_order",
        "kind",
        "source",
        "model",
        "agent_profile_id",
        "worktree",
        "autotitle",
        "max_iterations",
        "max_budget_per_run",
    }
)


def _origin(raw: str) -> str:
    """Require one fixed HTTPS origin; never send the API key over cleartext."""
    if not raw or raw != raw.strip() or "?" in raw or "#" in raw:
        raise RuntimeError("KULE_OPENHANDS_API_URL must be an HTTPS origin")
    base = raw.rstrip("/")
    try:
        parsed = urlsplit(base)
        port = parsed.port
    except ValueError:
        raise RuntimeError("KULE_OPENHANDS_API_URL must be an HTTPS origin") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise RuntimeError("KULE_OPENHANDS_API_URL must be an HTTPS origin")
    return base


def _api_key(raw: str) -> str:
    """A dedicated service key, never a browser cookie or broad host credential."""
    if (
        not raw
        or len(raw) > 4096
        or raw != raw.strip()
        or any(not 33 <= ord(character) <= 126 for character in raw)
    ):
        raise RuntimeError("KULE_OPENHANDS_API_KEY is missing or malformed")
    return raw


def _workspace_root(raw: str) -> str:
    if not raw or not raw.startswith("/") or "\x00" in raw or "\\" in raw:
        raise RuntimeError("KULE_OPENHANDS_WORKSPACE_ROOT must be an absolute POSIX path")
    root = posixpath.normpath(raw)
    if root == "/" or root == "//" or not root.startswith("/"):
        raise RuntimeError("KULE_OPENHANDS_WORKSPACE_ROOT must not be the filesystem root")
    return root


@lru_cache(maxsize=1)
def _load_spec() -> dict[str, Any]:
    try:
        with _SPEC.open(encoding="utf-8") as stream:
            spec = json.load(stream)
    except (OSError, ValueError):
        raise RuntimeError("Kule OpenHands OpenAPI fixture is missing or invalid") from None
    if not isinstance(spec, dict) or spec.get("info", {}).get("version") != _SPEC_VERSION:
        raise RuntimeError(f"Kule OpenHands OpenAPI fixture must be pinned to {_SPEC_VERSION}")
    return spec


def _restricted_spec() -> dict[str, Any]:
    """Keep only allowlisted operations, parameters and request-body fields."""
    spec = copy.deepcopy(_load_spec())
    source_paths = spec.get("paths")
    if not isinstance(source_paths, dict):
        raise RuntimeError("Kule OpenHands OpenAPI fixture has no paths")

    paths: dict[str, dict[str, Any]] = {}
    for operation_id, endpoint in _ENDPOINTS.items():
        operation = source_paths.get(endpoint.path, {}).get(endpoint.method)
        if not isinstance(operation, dict) or operation.get("operationId") != operation_id:
            raise RuntimeError(f"Kule OpenHands fixture is missing {operation_id}")
        operation = copy.deepcopy(operation)
        operation["parameters"] = [
            parameter
            for parameter in operation.get("parameters", [])
            if parameter.get("name") in endpoint.params
        ]
        path_operations = paths.setdefault(endpoint.path, {})
        if endpoint.method in path_operations:
            raise RuntimeError("Kule OpenHands endpoint allowlist collides")
        path_operations[endpoint.method] = operation

    spec["paths"] = paths
    schemas = spec.get("components", {}).get("schemas", {})
    _restrict_schemas(schemas)
    return spec


def _properties(schema: dict[str, Any]) -> dict[str, Any]:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise RuntimeError("Kule OpenHands request schema has no properties")
    return properties


def _restrict_schemas(schemas: dict[str, Any]) -> None:
    start = schemas.get("StartConversationRequest")
    if not isinstance(start, dict):
        raise RuntimeError("Kule OpenHands fixture has no StartConversationRequest")
    start["properties"] = {
        name: value for name, value in _properties(start).items() if name in _START_FIELDS
    }
    start["required"] = ["workspace", "agent_profile_id"]
    start["additionalProperties"] = False
    profile = start["properties"]["agent_profile_id"]
    start["properties"]["agent_profile_id"] = {
        "type": "string",
        "format": "uuid",
        "title": profile.get("title", "Agent Profile Id"),
        "description": profile.get("description", ""),
    }
    # Keep the native worktree lifecycle, but cap a single agent run.
    iterations = start["properties"].get("max_iterations", {})
    iterations["maximum"] = 1000
    tags = start["properties"].get("tags", {})
    if isinstance(tags.get("additionalProperties"), dict):
        tags["additionalProperties"]["maxLength"] = 256

    workspace = schemas.get("LocalWorkspace-Input")
    if not isinstance(workspace, dict):
        raise RuntimeError("Kule OpenHands fixture has no LocalWorkspace-Input")
    workspace["properties"] = {"working_dir": _properties(workspace)["working_dir"]}
    workspace["required"] = ["working_dir"]
    workspace["additionalProperties"] = False

    message = schemas.get("SendMessageRequest")
    if not isinstance(message, dict):
        raise RuntimeError("Kule OpenHands fixture has no SendMessageRequest")
    message_properties = _properties(message)
    content = message_properties["content"]
    content["items"] = {"$ref": "#/components/schemas/TextContent"}
    content["maxItems"] = _MAX_MESSAGE_BLOCKS
    message["properties"] = {"content": content, "run": message_properties["run"]}
    message["required"] = ["content"]
    message["additionalProperties"] = False

    text = schemas.get("TextContent")
    if not isinstance(text, dict):
        raise RuntimeError("Kule OpenHands fixture has no TextContent")
    text["properties"]["text"]["maxLength"] = _MAX_MESSAGE_BYTES


def _route_type(route: Any, route_type: MCPType) -> MCPType:
    """Fail closed for any operation that escaped the schema reduction."""
    return MCPType.TOOL if route.operation_id in _ENDPOINTS else MCPType.EXCLUDE


def _component(route: Any, component: Any) -> None:
    endpoint = _ENDPOINTS.get(route.operation_id or "")
    if endpoint is not None:
        component.tags = {endpoint.tier}


def _client(origin: str, key: str, timeout_seconds: float) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        base_url=origin,
        headers={_API_KEY_HEADER: key},
        timeout=max(1.0, min(20.0, timeout_seconds - 1.0)),
        follow_redirects=False,
        trust_env=False,
    )


@asynccontextmanager
async def _closing_client(client: httpx2.AsyncClient):
    try:
        yield
    finally:
        await client.aclose()


def _message_size(message: Any) -> int | None:
    """Validate a text-only Kule message; return its UTF-8 size."""
    if not isinstance(message, dict) or set(message) - {"content", "run"}:
        return None
    if "run" in message and not isinstance(message["run"], bool):
        return None
    content = message.get("content")
    if not isinstance(content, list) or not 1 <= len(content) <= _MAX_MESSAGE_BLOCKS:
        return None
    total = 0
    for block in content:
        if not isinstance(block, dict) or set(block) - {"text", "type", "cache_prompt"}:
            return None
        if "cache_prompt" in block and not isinstance(block["cache_prompt"], bool):
            return None
        if block.get("type", "text") != "text" or not isinstance(block.get("text"), str):
            return None
        try:
            size = len(block["text"].encode("utf-8"))
        except UnicodeError:
            return None
        if size > _MAX_MESSAGE_BYTES:
            return None
        total += size
    return total if total <= _MAX_MESSAGE_TOTAL_BYTES else None


def _conversation_id(value: Any) -> str:
    if not isinstance(value, str):
        raise AuthorizationError("OpenHands conversation target is not permitted")
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise AuthorizationError("OpenHands conversation target is not permitted") from None


def _event_id(value: Any) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise AuthorizationError("OpenHands event target is not permitted")
    if any(ord(character) < 32 for character in value) or any(
        character in value for character in "/\\?#"
    ):
        raise AuthorizationError("OpenHands event target is not permitted")


def _ref(value: Any, *, prefix: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    if prefix and value == "":
        return True
    if not (_BRANCH_PREFIX if prefix else _BRANCH).fullmatch(value):
        return False
    if any(part in value for part in ("..", "@{", "//")):
        return False
    if not prefix and (value.endswith("/") or value.endswith(".lock")):
        return False
    return True


def _audit_content(message: Any) -> dict[str, Any]:
    size = _message_size(message)
    if size is None:
        return {"valid": False, "reason": "type-or-size"}
    content = message["content"]
    blob = "\n".join(block["text"] for block in content).encode("utf-8")
    return {
        "valid": True,
        "blocks": len(content),
        "bytes": size,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def audit_arguments(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Audit only bounded routing metadata, never prompts or message bodies."""
    result: dict[str, Any] = {}
    for name, value in args.items():
        if name not in _AUDIT_FIELDS:
            continue
        if isinstance(value, str):
            result[name] = value[:1024]
        elif value is None or isinstance(value, bool | int | float):
            result[name] = value
    workspace = args.get("workspace")
    if isinstance(workspace, dict) and isinstance(workspace.get("working_dir"), str):
        result["working_dir"] = workspace["working_dir"][:1024]
    if "initial_message" in args:
        result["initial_message"] = _audit_content(args["initial_message"])
    if "content" in args:
        message = {"content": args["content"]}
        if "run" in args:
            message["run"] = args["run"]
        result["content"] = _audit_content(message)
    return result


class _TargetGuard(Middleware):
    """Authorize the target path and reject unsafe message shapes before HTTP."""

    def __init__(self, workspace_root: str) -> None:
        self.workspace_root = workspace_root

    async def on_call_tool(self, context, call_next):
        name = context.message.name
        arguments = dict(context.message.arguments or {})

        if name == "start_conversation":
            self._start(arguments)
        elif name == "send_message":
            if set(arguments) - {"conversation_id", "content", "run"}:
                raise AuthorizationError("OpenHands message is not permitted")
            _conversation_id(arguments.get("conversation_id"))
            message = {"content": arguments.get("content")}
            if "run" in arguments:
                message["run"] = arguments["run"]
            if _message_size(message) is None:
                raise AuthorizationError("OpenHands message is not permitted")
        elif name == "switch_acp_model":
            if set(arguments) != {"conversation_id", "model"}:
                raise AuthorizationError("OpenHands model switch is not permitted")
            _conversation_id(arguments.get("conversation_id"))
            model = arguments.get("model")
            if not isinstance(model, str) or not _MODEL.fullmatch(model):
                raise AuthorizationError("OpenHands model identifier is not permitted")
        elif name in {
            "get_conversation",
            "get_conversation_runtime",
            "search_events",
            "run_conversation",
            "interrupt_conversation",
            "pause_conversation",
        }:
            _conversation_id(arguments.get("conversation_id"))
        elif name == "get_event":
            _conversation_id(arguments.get("conversation_id"))
            _event_id(arguments.get("event_id"))

        return await call_next(context)

    def _start(self, arguments: dict[str, Any]) -> None:
        if set(arguments) - _START_FIELDS:
            raise AuthorizationError("OpenHands launch field is not permitted")
        workspace = arguments.get("workspace")
        if not isinstance(workspace, dict) or set(workspace) != {"working_dir"}:
            raise AuthorizationError("OpenHands workspace target is not permitted")
        working_dir = workspace.get("working_dir")
        if not isinstance(working_dir, str) or len(working_dir) > 1024 or "\x00" in working_dir:
            raise AuthorizationError("OpenHands workspace target is not permitted")
        normal = posixpath.normpath(working_dir)
        if not normal.startswith(self.workspace_root + "/"):
            raise AuthorizationError("OpenHands workspace target is outside the approved root")

        worktree = arguments.get("worktree", False)
        if not isinstance(worktree, bool):
            raise AuthorizationError("OpenHands worktree flag is not permitted")
        options = arguments.get("worktree_options")
        if options is not None and not _worktree_options(options):
            raise AuthorizationError("OpenHands worktree options are not permitted")
        if not worktree and options is not None:
            raise AuthorizationError("OpenHands worktree options require worktree=true")

        if arguments.get("initial_message") is not None:
            if _message_size(arguments["initial_message"]) is None:
                raise AuthorizationError("OpenHands message is not permitted")

        profile = arguments.get("agent_profile_id")
        if not isinstance(profile, str) or not 1 <= len(profile) <= 200:
            raise AuthorizationError("OpenHands agent profile is not permitted")
        try:
            uuid.UUID(profile)
        except (ValueError, AttributeError):
            raise AuthorizationError("OpenHands agent profile is not permitted") from None

        if "max_iterations" in arguments:
            iterations = arguments["max_iterations"]
            if (
                isinstance(iterations, bool)
                or not isinstance(iterations, int)
                or not 1 <= iterations <= 1000
            ):
                raise AuthorizationError("OpenHands iteration limit is not permitted")
        if arguments.get("max_budget_per_run") is not None:
            budget = arguments["max_budget_per_run"]
            if (
                isinstance(budget, bool)
                or not isinstance(budget, int | float)
                or not math.isfinite(budget)
                or budget <= 0
            ):
                raise AuthorizationError("OpenHands budget is not permitted")
        if "autotitle" in arguments and not isinstance(arguments["autotitle"], bool):
            raise AuthorizationError("OpenHands autotitle flag is not permitted")
        if "tags" in arguments:
            tags = arguments["tags"]
            if (
                not isinstance(tags, dict)
                or len(tags) > 32
                or any(
                    not isinstance(key, str)
                    or not _TAG_KEY.fullmatch(key)
                    or not isinstance(value, str)
                    or len(value) > 256
                    for key, value in tags.items()
                )
            ):
                raise AuthorizationError("OpenHands tags are not permitted")


def _worktree_options(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) - {"base", "ref", "branch_prefix"}:
        return False
    base = value.get("base", "default_branch")
    if base not in {"default_branch", "head", "ref"}:
        return False
    ref = value.get("ref")
    if ref is not None and not _ref(ref):
        return False
    if base == "ref" and ref is None:
        return False
    prefix = value.get("branch_prefix", "openhands/")
    return _ref(prefix, prefix=True)


def mount(
    mcp: FastMCP,
    *,
    client: httpx2.AsyncClient | None = None,
    timeout_seconds: float = 20.0,
) -> None:
    """Mount the reviewed Canvas management tools; client injection is for tests."""
    root = _workspace_root(os.environ.get("KULE_OPENHANDS_WORKSPACE_ROOT", _DEFAULT_WORKSPACE_ROOT))
    lifespan = None
    if client is None:
        origin = _origin(os.environ.get("KULE_OPENHANDS_API_URL", ""))
        client = _client(
            origin, _api_key(os.environ.get("KULE_OPENHANDS_API_KEY", "")), timeout_seconds
        )
        lifespan = _closing_client(client)

    backend = FastMCP.from_openapi(
        _restricted_spec(),
        client=client,
        name="openhands",
        route_map_fn=_route_type,
        mcp_component_fn=_component,
        mcp_names={operation_id: endpoint.tool for operation_id, endpoint in _ENDPOINTS.items()},
        # Canvas unions are broad; Kule still bounds the serialized result.
        validate_output=False,
        # Never silently drop a forbidden argument such as secrets or hooks.
        strict_input_validation=True,
        lifespan=lifespan,
    )
    backend.add_middleware(_TargetGuard(root))
    # Parent middleware gates tools, not arbitrary upstream resources/prompts.
    backend.disable(components={"resource", "template", "prompt"})
    mcp.mount(backend, namespace="oh")
