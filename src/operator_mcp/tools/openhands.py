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

import base64
import copy
import hashlib
import hmac
import json
import math
import os
import posixpath
import re
import ssl
import uuid
from collections.abc import Mapping
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
from fastmcp.tools.base import ToolResult

from ..authz import OPERATE, READ

_SPEC = Path(__file__).resolve().parent.parent / "openapi" / "openhands-1.62.0.json"
_SPEC_VERSION = "1.62.0"
_API_KEY_HEADER = "X-Session-API-Key"
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_EFFORT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_REPOSITORY = re.compile(r"^(?!\.{1,2}/)(?!.*/\.{1,2}$)[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$")
_BRANCH_PREFIX = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._/-]{0,200})?$")
_TAG_KEY = re.compile(r"^[a-z0-9]{1,64}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_MESSAGE_BLOCKS = 32
_MAX_MESSAGE_BYTES = 32 * 1024
_MAX_MESSAGE_TOTAL_BYTES = 64 * 1024
_MAX_BUDGET_PER_RUN = 1000.0
_MAX_LIST_PAGES = 5
_CURSOR_PREFIX = "gc1."
_CURSOR_NONCE_BYTES = 12
# FastMCP forwards inbound MCP HTTP headers to the upstream request. Keep only
# the transport headers Canvas needs so a caller cannot smuggle observability
# tags, cookies, credentials or other headers through the gateway. The service
# key is deliberately absent: it is re-applied from configuration after this
# filter, so an inbound X-Session-API-Key can never replace it.
_ALLOWED_REQUEST_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "content-type",
        "user-agent",
    }
)
# Only lifecycle metadata is returned. ConversationInfo also carries the secret
# registry, hook definitions, agent settings, arbitrary agent state and a
# remote workspace API key; none of those leave the gateway. Relationship IDs
# (parent, fork, child, leaf event) are also dropped: Canvas does not check the
# referenced conversation's repository tag, so returning them would disclose an
# ID that a direct read of that conversation would deny.
_SAFE_CONVERSATION_FIELDS = frozenset(
    {
        "id",
        "title",
        "execution_status",
        "created_at",
        "updated_at",
        "tags",
        "workspace",
        "max_iterations",
        "max_budget_per_run",
        "stuck_detection",
        "current_model_id",
        "available_models",
        "current_effort",
        "available_efforts",
        "supports_runtime_model_switch",
        "metrics",
    }
)
_SAFE_WORKSPACE_FIELDS = ("working_dir", "kind")
_SAFE_MODEL_FIELDS = ("model_id", "name", "description")
_SAFE_METRIC_FIELDS = (
    "model_name",
    "accumulated_cost",
    "max_budget_per_task",
    "accumulated_token_usage",
)
_CONVERSATION_TOOLS = frozenset({"start_conversation", "get_conversation"})


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
    "get_conversation_api_conversations__conversation_id__get": _Endpoint(
        "get_conversation",
        READ,
        "get",
        "/api/conversations/{conversation_id}",
        frozenset({"conversation_id"}),
    ),
    "update_conversation_api_conversations__conversation_id__patch": _Endpoint(
        "rename_conversation",
        OPERATE,
        "patch",
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
    "switch_conversation_acp_effort_api_conversations__conversation_id__switch_acp_effort_post": (
        _Endpoint(
            "switch_acp_effort",
            OPERATE,
            "post",
            "/api/conversations/{conversation_id}/switch_acp_effort",
            frozenset({"conversation_id"}),
        )
    ),
}

_START_FIELDS = frozenset(
    {
        "repository",
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
        "repository",
        "conversation_id",
        "event_id",
        "limit",
        "page_id",
        "status",
        "sort_order",
        "kind",
        "source",
        "model",
        "effort",
        "title",
        "agent_profile_id",
        "worktree",
        "autotitle",
        "max_iterations",
        "max_budget_per_run",
    }
)


def _allow_cluster_http(env: Mapping[str, str]) -> bool:
    """Require explicit opt-in before permitting cluster-local HTTP."""
    return env.get("KULE_OPENHANDS_ALLOW_CLUSTER_HTTP") == "1"


def _is_cluster_http_host(hostname: str) -> bool:
    """Allow only loopback or <service>.<namespace>.svc[.cluster.local]."""
    host = hostname.lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    parts = host.split(".")
    if len(parts) == 5 and parts[2:] == ["svc", "cluster", "local"]:
        return all(_DNS_LABEL.fullmatch(label) for label in parts[:2])
    if len(parts) == 3 and parts[2:] == ["svc"]:
        return all(_DNS_LABEL.fullmatch(label) for label in parts[:2])
    return False


def _origin(raw: str, *, allow_cluster_http: bool = False) -> str:
    """Require a fixed HTTPS origin unless cluster-local HTTP is explicitly opted in."""
    message = (
        "KULE_OPENHANDS_API_URL must be an HTTPS origin or a cluster-local HTTP service origin"
        if allow_cluster_http
        else "KULE_OPENHANDS_API_URL must be an HTTPS origin"
    )
    if not raw or raw != raw.strip() or "?" in raw or "#" in raw:
        raise RuntimeError(message)
    base = raw.rstrip("/")
    try:
        parsed = urlsplit(base)
        port = parsed.port
    except ValueError:
        raise RuntimeError(message) from None
    scheme_ok = parsed.scheme == "https" or (
        parsed.scheme == "http"
        and allow_cluster_http
        and bool(parsed.hostname)
        and _is_cluster_http_host(parsed.hostname)
    )
    if (
        not scheme_ok
        or not parsed.hostname
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise RuntimeError(message)
    return base


def _api_key(raw: str, *, required: bool = True) -> str | None:
    """A dedicated service key, never a browser cookie or broad host credential."""
    if not required and raw == "":
        return None
    if (
        not raw
        or len(raw) > 4096
        or raw != raw.strip()
        or any(not 33 <= ord(character) <= 126 for character in raw)
    ):
        raise RuntimeError("KULE_OPENHANDS_API_KEY is missing or malformed")
    return raw


def _mapped_path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 1024:
        raise RuntimeError("KULE_OPENHANDS_REPOSITORIES paths must be absolute POSIX paths")
    if (
        "\x00" in value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/")[1:])
    ):
        raise RuntimeError("KULE_OPENHANDS_REPOSITORIES paths must be normalized")
    normal = posixpath.normpath(value)
    if normal == "/" or normal == "//" or not normal.startswith("/"):
        raise RuntimeError("KULE_OPENHANDS_REPOSITORIES must not map to the filesystem root")
    return normal


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys that json.loads would silently collapse."""
    data: dict[str, Any] = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate key")
        data[key] = value
    return data


def _repositories(raw: str) -> dict[str, str]:
    """Require an exact approved owner/name -> Canvas source path mapping."""
    if not raw or len(raw) > 16384:
        raise RuntimeError("KULE_OPENHANDS_REPOSITORIES must be a non-empty JSON object")
    try:
        data = json.loads(raw, object_pairs_hook=_unique_pairs)
    except ValueError:
        raise RuntimeError(
            "KULE_OPENHANDS_REPOSITORIES must be valid JSON without duplicate names"
        ) from None
    if not isinstance(data, dict) or not 1 <= len(data) <= 64:
        raise RuntimeError("KULE_OPENHANDS_REPOSITORIES must map 1 to 64 repositories")
    approved: dict[str, str] = {}
    paths: set[str] = set()
    for name, value in data.items():
        if not isinstance(name, str) or not _REPOSITORY.fullmatch(name):
            raise RuntimeError("KULE_OPENHANDS_REPOSITORIES has an invalid repository")
        repository = name.lower()
        path = _mapped_path(value)
        if repository in approved or path in paths:
            raise RuntimeError("KULE_OPENHANDS_REPOSITORIES has a duplicate scope")
        approved[repository] = path
        paths.add(path)
    return approved


def settings_from_env(
    env: Mapping[str, str] | None = None,
) -> tuple[dict[str, str], str, str | None]:
    """Validate the opt-in Canvas settings without creating a client or calling Canvas."""
    values = os.environ if env is None else env
    repositories = _repositories(values.get("KULE_OPENHANDS_REPOSITORIES", ""))
    allow_http = _allow_cluster_http(values)
    origin = _origin(values.get("KULE_OPENHANDS_API_URL", ""), allow_cluster_http=allow_http)
    key_required = not (allow_http and origin.startswith("http://"))
    key = _api_key(values.get("KULE_OPENHANDS_API_KEY", ""), required=key_required)
    return repositories, origin, key


def _tls_verify(
    env: Mapping[str, str] | None = None, *, origin: str | None = None
) -> bool | ssl.SSLContext:
    """Use explicit integration-local trust, never ambient CA or proxy settings."""
    values = os.environ if env is None else env
    if "KULE_OPENHANDS_CA_FILE" not in values:
        return True
    if origin is not None and origin.startswith("http://"):
        raise RuntimeError("KULE_OPENHANDS_CA_FILE requires an HTTPS origin")
    raw = values["KULE_OPENHANDS_CA_FILE"]
    try:
        if not raw or raw != raw.strip() or not Path(raw).is_absolute():
            raise ValueError("invalid CA path")
        return ssl.create_default_context(cafile=raw)
    except (OSError, ValueError):
        raise RuntimeError(
            "KULE_OPENHANDS_CA_FILE must be an absolute readable CA bundle"
        ) from None


def validate_settings(env: Mapping[str, str] | None = None) -> None:
    """Offline config preflight: validate settings and explicitly configured trust."""
    _, origin, _ = settings_from_env(env)
    _tls_verify(env, origin=origin)


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
    budget = start["properties"].get("max_budget_per_run", {})
    for option in budget.get("anyOf", []):
        if isinstance(option, dict) and option.get("type") == "number":
            option["maximum"] = _MAX_BUDGET_PER_RUN
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

    update = schemas.get("UpdateConversationRequest")
    if not isinstance(update, dict):
        raise RuntimeError("Kule OpenHands fixture has no UpdateConversationRequest")
    update["properties"] = {
        "title": {
            "type": "string",
            "minLength": 1,
            "maxLength": 200,
            "title": "Title",
            "description": "New conversation title.",
        }
    }
    update["required"] = ["title"]
    update["additionalProperties"] = False


def _route_type(route: Any, route_type: MCPType) -> MCPType:
    """Fail closed for any operation that escaped the schema reduction."""
    return MCPType.TOOL if route.operation_id in _ENDPOINTS else MCPType.EXCLUDE


def _component(route: Any, component: Any) -> None:
    endpoint = _ENDPOINTS.get(route.operation_id or "")
    if endpoint is None:
        return
    component.tags = {endpoint.tier}
    if endpoint.tool == "list_agent_profiles":
        return
    # Repository scope is a Kule target-authorization parameter. It is not sent
    # upstream; the guard removes it and enforces the native kulerepo tag.
    properties = component.parameters.setdefault("properties", {})
    if endpoint.tool == "list_conversations":
        if isinstance(properties.get("page_id"), dict):
            properties["page_id"]["maxLength"] = 256
            properties["page_id"]["description"] = (
                "Gateway continuation cursor from the previous next_page_id; "
                "never a native Canvas conversation ID."
            )
        if isinstance(properties.get("sort_order"), dict):
            properties["sort_order"]["enum"] = ["CREATED_AT", "CREATED_AT_DESC"]
    properties["repository"] = {
        "type": "string",
        "pattern": _REPOSITORY.pattern,
        "maxLength": 150,
        "title": "Repository",
        "description": "Canonical owner/name; enforced against the native kulerepo tag.",
    }
    required = list(component.parameters.get("required") or [])
    if "repository" not in required:
        required.append("repository")
    component.parameters["required"] = required


class _ScopedClient(httpx2.AsyncClient):
    """Strip caller-supplied headers and pin the configured Canvas key."""

    def __init__(self, *args: Any, api_key: str | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._canvas_api_key = api_key

    async def send(self, request: httpx2.Request, **kwargs: Any) -> httpx2.Response:
        for name in tuple(request.headers.keys()):
            if name.lower() not in _ALLOWED_REQUEST_HEADERS:
                del request.headers[name]
        # Rebuild framing from the configured URL and the serialized body.
        # Inbound Host, Content-Length and Transfer-Encoding are never trusted.
        host = request.url.host
        if ":" in host:
            host = f"[{host}]"
        port = request.url.port
        default_port = 443 if request.url.scheme == "https" else 80
        if port is not None and port != default_port:
            host = f"{host}:{port}"
        request.headers["Host"] = host
        try:
            body = request.content
        except httpx2.RequestNotRead:
            body = None
        if body is None:
            request.headers.pop("Content-Length", None)
        else:
            request.headers["Content-Length"] = str(len(body))
        if self._canvas_api_key is not None:
            # Re-apply after filtering: FastMCP may add inbound MCP headers to
            # the built request, including a caller-controlled session key.
            request.headers[_API_KEY_HEADER] = self._canvas_api_key
        return await super().send(request, **kwargs)


def _client(
    origin: str, key: str | None, timeout_seconds: float, *, verify: bool | ssl.SSLContext = True
) -> httpx2.AsyncClient:
    headers = {_API_KEY_HEADER: key} if key is not None else {}
    return _ScopedClient(
        base_url=origin,
        headers=headers,
        api_key=key,
        timeout=max(1.0, min(20.0, timeout_seconds - 1.0)),
        follow_redirects=False,
        trust_env=False,
        verify=verify,
    )


def _closing_lifespan(client: httpx2.AsyncClient):
    """Build the callable FastMCP expects; it passes the mounted server here."""

    @asynccontextmanager
    async def lifespan(_server: FastMCP):
        try:
            yield {}
        finally:
            await client.aclose()

    return lifespan


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


def _repository(value: Any, approved: dict[str, str]) -> str:
    if not isinstance(value, str) or len(value) > 150 or not _REPOSITORY.fullmatch(value):
        raise AuthorizationError("OpenHands repository target is not permitted")
    # GitHub owner/name scope is case-insensitive; keep one native tag value.
    repository = value.lower()
    if repository not in approved:
        raise AuthorizationError("OpenHands repository target is not permitted")
    return repository


def _event_id(value: Any) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise AuthorizationError("OpenHands event target is not permitted")
    if any(ord(character) < 32 for character in value) or any(
        character in value for character in "/\\?#"
    ):
        raise AuthorizationError("OpenHands event target is not permitted")


def _cursor_key(api_key: str | None) -> bytes:
    """Derive a stable signing key; tests without a key get a per-mount key."""
    if api_key:
        return hmac.new(api_key.encode("utf-8"), b"kule-openhands-cursor", hashlib.sha256).digest()
    return os.urandom(32)


def _cursor_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    """HMAC-SHA256 counter-mode keystream for the opaque page cursor."""
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block = hmac.new(
            key,
            b"kule-openhands-cursor\x00" + nonce + counter.to_bytes(4, "big"),
            hashlib.sha256,
        ).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def _encode_cursor(conversation_id: str, key: bytes) -> str:
    """Seal a native page position so excluded conversation IDs stay opaque.

    Canvas continues a scan from a native conversation UUID. The cursor is
    encrypted and authenticated so a caller cannot read a conversation ID that
    was filtered out of the page, and any tampering is denied.
    """
    nonce = os.urandom(_CURSOR_NONCE_BYTES)
    try:
        raw = uuid.UUID(conversation_id).bytes
    except (ValueError, AttributeError):
        raise AuthorizationError("OpenHands pagination is not permitted") from None
    sealed = bytes(
        left ^ right for left, right in zip(raw, _cursor_stream(key, nonce, len(raw)), strict=True)
    )
    payload = base64.urlsafe_b64encode(nonce + sealed).decode("ascii").rstrip("=")
    signature = hmac.new(key, b"gc1:" + payload.encode("ascii"), hashlib.sha256).hexdigest()[:32]
    return f"{_CURSOR_PREFIX}{signature}.{payload}"


def _decode_cursor(value: Any, key: bytes) -> str:
    """Return the native page position from a signed gateway cursor."""
    if not isinstance(value, str) or len(value) > 256 or not value.startswith(_CURSOR_PREFIX):
        raise AuthorizationError("OpenHands pagination is not permitted")
    signature, separator, payload = value[len(_CURSOR_PREFIX) :].partition(".")
    if (
        not separator
        or len(signature) != 32
        or any(character not in "0123456789abcdef" for character in signature)
        or not payload
    ):
        raise AuthorizationError("OpenHands pagination is not permitted")
    try:
        expected = hmac.new(key, b"gc1:" + payload.encode("ascii"), hashlib.sha256).hexdigest()[:32]
    except UnicodeError:
        raise AuthorizationError("OpenHands pagination is not permitted") from None
    if not hmac.compare_digest(signature, expected):
        raise AuthorizationError("OpenHands pagination is not permitted")
    try:
        blob = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    except (ValueError, UnicodeError):
        raise AuthorizationError("OpenHands pagination is not permitted") from None
    if len(blob) != _CURSOR_NONCE_BYTES + 16:
        raise AuthorizationError("OpenHands pagination is not permitted")
    nonce, sealed = blob[:_CURSOR_NONCE_BYTES], blob[_CURSOR_NONCE_BYTES:]
    raw = bytes(
        left ^ right
        for left, right in zip(sealed, _cursor_stream(key, nonce, len(sealed)), strict=True)
    )
    try:
        return str(uuid.UUID(bytes=raw))
    except (ValueError, AttributeError):
        raise AuthorizationError("OpenHands pagination is not permitted") from None


def _safe_conversation(value: Any) -> dict[str, Any]:
    """Project a native ConversationInfo onto lifecycle-only fields."""
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        raise AuthorizationError("OpenHands conversation response is invalid")
    result = {
        name: copy.deepcopy(value[name])
        for name in _SAFE_CONVERSATION_FIELDS
        if name in value and name not in {"workspace", "available_models", "metrics"}
    }
    workspace = value.get("workspace")
    if isinstance(workspace, dict):
        result["workspace"] = {
            name: workspace[name] for name in _SAFE_WORKSPACE_FIELDS if name in workspace
        }
    models = value.get("available_models")
    if isinstance(models, list):
        result["available_models"] = [
            {name: item[name] for name in _SAFE_MODEL_FIELDS if name in item}
            for item in models
            if isinstance(item, dict)
        ]
    metrics = value.get("metrics")
    if isinstance(metrics, dict):
        result["metrics"] = {
            name: copy.deepcopy(metrics[name]) for name in _SAFE_METRIC_FIELDS if name in metrics
        }
    profile = value.get("launched_agent_profile")
    if isinstance(profile, dict) and isinstance(profile.get("agent_profile_id"), str):
        result["agent_profile_id"] = profile["agent_profile_id"]
    return result


def _project_result(name: str, result: ToolResult) -> ToolResult:
    if name not in _CONVERSATION_TOOLS:
        return result
    data = result.structured_content
    return ToolResult(structured_content=_safe_conversation(data), meta=result.meta)


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
        elif value is None or isinstance(value, bool):
            result[name] = value
        elif isinstance(value, int):
            # Keep the audit writer away from unbounded integer conversion.
            result[name] = value if -(2**53) <= value <= 2**53 else "out-of-range"
        elif isinstance(value, float):
            result[name] = value if math.isfinite(value) else "non-finite"
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
    """Enforce repository scope and safe launch targets before any HTTP call."""

    def __init__(
        self,
        client: httpx2.AsyncClient,
        repositories: dict[str, str],
        cursor_key: bytes,
    ) -> None:
        self.client = client
        self.repositories = repositories
        self.cursor_key = cursor_key

    async def on_call_tool(self, context, call_next):
        name = context.message.name
        arguments = dict(context.message.arguments or {})
        repository: str | None = None
        cursor_native: str | None = None

        if name == "start_conversation":
            self._start(arguments)
            repository = self._repository(arguments.pop("repository"))
            tags = dict(arguments.get("tags") or {})
            tags["kulerepo"] = repository
            arguments["tags"] = tags
        elif name == "list_conversations":
            repository = self._repository(arguments.pop("repository", None))
            self._pagination(arguments)
            sort_order = arguments.get("sort_order")
            # A continuation anchored on a conversation ID is only stable while
            # the ordering key is immutable. Reject updated-time order instead
            # of silently skipping sessions that move after a rename.
            if sort_order is not None and (
                not isinstance(sort_order, str)
                or sort_order not in {"CREATED_AT", "CREATED_AT_DESC"}
            ):
                raise AuthorizationError("OpenHands sort order is not permitted")
            if arguments.get("page_id") is not None:
                cursor_native = _decode_cursor(arguments["page_id"], self.cursor_key)
                # Canvas matches page_id against UUID.hex, not the hyphenated
                # UUID string it returns in conversation records.
                arguments["page_id"] = uuid.UUID(cursor_native).hex
            else:
                arguments.pop("page_id", None)
            # An explicit null filter is not a Canvas enum value. Drop it here as
            # well as in _page so the first request matches follow-up pages.
            for nullable in ("status", "sort_order"):
                if arguments.get(nullable) is None:
                    arguments.pop(nullable, None)
        elif name == "send_message":
            repository, conversation_id = self._scope(
                arguments, {"repository", "conversation_id", "content", "run"}
            )
            message = {"content": arguments.get("content")}
            if "run" in arguments:
                message["run"] = arguments["run"]
            if _message_size(message) is None:
                raise AuthorizationError("OpenHands message is not permitted")
            await self._verify_repository(repository, conversation_id)
        elif name == "switch_acp_model":
            repository, conversation_id = self._scope(
                arguments, {"repository", "conversation_id", "model"}
            )
            model = arguments.get("model")
            if not isinstance(model, str) or not _MODEL.fullmatch(model):
                raise AuthorizationError("OpenHands model identifier is not permitted")
            await self._verify_repository(repository, conversation_id)
        elif name == "switch_acp_effort":
            repository, conversation_id = self._scope(
                arguments, {"repository", "conversation_id", "effort"}
            )
            effort = arguments.get("effort")
            if not isinstance(effort, str) or not _EFFORT.fullmatch(effort):
                raise AuthorizationError("OpenHands effort identifier is not permitted")
            await self._verify_repository(repository, conversation_id)
        elif name == "rename_conversation":
            repository, conversation_id = self._scope(
                arguments, {"repository", "conversation_id", "title"}
            )
            title = arguments.get("title")
            if (
                not isinstance(title, str)
                or not 1 <= len(title) <= 200
                or any(ord(character) < 32 for character in title)
            ):
                raise AuthorizationError("OpenHands conversation title is not permitted")
            await self._verify_repository(repository, conversation_id)
        elif name == "get_event":
            repository, conversation_id = self._scope(
                arguments, {"repository", "conversation_id", "event_id"}
            )
            _event_id(arguments.get("event_id"))
            await self._verify_repository(repository, conversation_id)
        elif name == "search_events":
            repository, conversation_id = self._scope(
                arguments,
                {
                    "repository",
                    "conversation_id",
                    "page_id",
                    "limit",
                    "kind",
                    "source",
                    "body",
                    "sort_order",
                    "timestamp__gte",
                    "timestamp__lt",
                },
            )
            self._pagination(arguments)
            await self._verify_repository(repository, conversation_id)
        elif name in {
            "get_conversation",
            "get_conversation_runtime",
            "run_conversation",
            "interrupt_conversation",
            "pause_conversation",
        }:
            repository, conversation_id = self._scope(arguments, {"repository", "conversation_id"})
            await self._verify_repository(repository, conversation_id)

        context.message.arguments = arguments
        result = await call_next(context)
        if name == "list_conversations":
            return await self._list_repository(result, repository, cursor_native, arguments)
        return _project_result(name, result)

    async def _list_repository(
        self,
        result: ToolResult,
        repository: str,
        cursor_native: str | None,
        arguments: dict[str, Any],
    ) -> ToolResult:
        """Filter by repository and continue with a gateway cursor.

        Canvas ``next_page_id`` is the next global conversation UUID, which may
        belong to another repository. Returning it would disclose an excluded
        conversation ID, so continuation seals that native position in an
        encrypted, authenticated cursor. Canvas treats ``page_id`` as an
        inclusive start, so the next call begins at the first unscanned
        conversation and never rebuilds the position from a returned item that
        could move in the sort order.
        """
        items: list[dict[str, Any]] = []
        next_native: str | None = None
        pages = 0
        truncated = False

        while True:
            data = result.structured_content
            if (
                not isinstance(data, dict)
                or not isinstance(data.get("items"), list)
                or not isinstance(data.get("next_page_id"), str | None)
            ):
                raise AuthorizationError("OpenHands conversation list is invalid")
            next_native = data.get("next_page_id")
            if pages == 0 and cursor_native is not None:
                first = data["items"][0] if data["items"] else None
                if not isinstance(first, dict) or first.get("id") != cursor_native:
                    raise AuthorizationError("OpenHands pagination cursor is stale")
            for item in data["items"]:
                if not isinstance(item, dict):
                    continue
                conversation = _safe_conversation(item)
                tags = conversation.get("tags")
                if isinstance(tags, dict) and tags.get("kulerepo") == repository:
                    items.append(conversation)
            pages += 1
            if items or next_native is None or pages >= _MAX_LIST_PAGES:
                truncated = not items and next_native is not None
                break
            result = await self._page(next_native, arguments)

        cursor = None if next_native is None else _encode_cursor(next_native, self.cursor_key)
        data = {"items": items, "next_page_id": cursor}
        if truncated:
            data["truncated"] = True
        return ToolResult(structured_content=data, meta=result.meta)

    async def _page(self, page_id: str, arguments: dict[str, Any]) -> ToolResult:
        params = {
            name: arguments[name]
            for name in ("limit", "status", "sort_order")
            if arguments.get(name) is not None
        }
        params["page_id"] = page_id
        try:
            response = await self.client.get("/api/conversations/search", params=params)
        except httpx2.HTTPError:
            raise AuthorizationError("OpenHands conversation list is not verified") from None
        if response.status_code != 200:
            raise AuthorizationError("OpenHands conversation list is not verified")
        try:
            data = response.json()
        except ValueError:
            raise AuthorizationError("OpenHands conversation list is not verified") from None
        return ToolResult(structured_content=data)

    @staticmethod
    def _pagination(arguments: dict[str, Any]) -> None:
        if "limit" in arguments:
            limit = arguments["limit"]
            if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
                raise AuthorizationError("OpenHands pagination is not permitted")
        if "page_id" in arguments:
            page_id = arguments["page_id"]
            if page_id is not None and (not isinstance(page_id, str) or len(page_id) > 1024):
                raise AuthorizationError("OpenHands pagination is not permitted")

    def _repository(self, value: Any) -> str:
        return _repository(value, self.repositories)

    def _scope(self, arguments: dict[str, Any], allowed: set[str]) -> tuple[str, str]:
        if set(arguments) - allowed:
            raise AuthorizationError("OpenHands conversation scope is not permitted")
        repository = self._repository(arguments.pop("repository", None))
        conversation_id = _conversation_id(arguments.get("conversation_id"))
        return repository, conversation_id

    async def _verify_repository(self, repository: str, conversation_id: str) -> None:
        """Verify the native kulerepo tag before any direct conversation action."""
        try:
            response = await self.client.get(f"/api/conversations/{conversation_id}")
        except httpx2.HTTPError:
            raise AuthorizationError("OpenHands conversation scope is not verified") from None
        if response.status_code != 200:
            raise AuthorizationError("OpenHands conversation scope is not verified")
        try:
            conversation = response.json()
        except ValueError:
            raise AuthorizationError("OpenHands conversation scope is not verified") from None
        if not isinstance(conversation, dict) or conversation.get("id") != conversation_id:
            raise AuthorizationError("OpenHands conversation scope is not verified")
        tags = conversation.get("tags")
        if not isinstance(tags, dict) or tags.get("kulerepo") != repository:
            raise AuthorizationError("OpenHands conversation is outside the requested repository")

    def _start(self, arguments: dict[str, Any]) -> None:
        if set(arguments) - _START_FIELDS:
            raise AuthorizationError("OpenHands launch field is not permitted")
        repository = self._repository(arguments.get("repository"))
        workspace = arguments.get("workspace")
        if not isinstance(workspace, dict) or set(workspace) != {"working_dir"}:
            raise AuthorizationError("OpenHands workspace target is not permitted")
        working_dir = workspace.get("working_dir")
        if not isinstance(working_dir, str) or len(working_dir) > 1024 or "\x00" in working_dir:
            raise AuthorizationError("OpenHands workspace target is not permitted")
        if posixpath.normpath(working_dir) != self.repositories[repository]:
            raise AuthorizationError(
                "OpenHands workspace target does not match the approved repository path"
            )

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
            if isinstance(budget, bool) or not isinstance(budget, int | float):
                raise AuthorizationError("OpenHands budget is not permitted")
            # Compare integer bounds before math.isfinite: a huge int would
            # raise OverflowError instead of producing a clean denial.
            if isinstance(budget, int):
                if not 1 <= budget <= _MAX_BUDGET_PER_RUN:
                    raise AuthorizationError("OpenHands budget is not permitted")
            elif not math.isfinite(budget) or not 0 < budget <= _MAX_BUDGET_PER_RUN:
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
            existing = tags.get("kulerepo")
            if existing is not None and existing.lower() != repository:
                raise AuthorizationError("OpenHands repository tag is not permitted")


def _worktree_options(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) - {"base", "ref", "branch_prefix"}:
        return False
    base = value.get("base", "default_branch")
    if not isinstance(base, str) or base not in {"default_branch", "head", "ref"}:
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
    lifespan = None
    api_key: str | None = None
    if client is None:
        repositories, origin, api_key = settings_from_env()
        client = _client(origin, api_key, timeout_seconds, verify=_tls_verify(origin=origin))
        lifespan = _closing_lifespan(client)
    else:
        repositories = _repositories(os.environ.get("KULE_OPENHANDS_REPOSITORIES", ""))

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
    backend.add_middleware(_TargetGuard(client, repositories, _cursor_key(api_key)))
    # Parent middleware gates tools, not arbitrary upstream resources/prompts.
    backend.disable(components={"resource", "template", "prompt"})
    mcp.mount(backend, namespace="oh")
