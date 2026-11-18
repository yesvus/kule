"""Typed OpenBao KVv2 metadata onboarding and status for operator callers.

This module is source-only. It does not contact OpenBao, hold a token, read or
write KV values, author ACL policies or roles, or provide a general secret
endpoint. It validates an approved profile and exact path, asks an injected
trusted executor to reserve or read KVv2 *metadata*, and returns metadata plus
owner-facing UI instructions.

The trusted executor is the reviewed ops#906 execution boundary, not a new
network client. No live adapter is included here. Until the executor exposes the
two fixed metadata actions named in ``docs/openbao.md``, this module must remain
unwired and must not claim that reservation or status is live.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from types import MappingProxyType
from typing import Annotated, Any, Protocol
from urllib.parse import quote, urlsplit

from fastmcp import FastMCP
from pydantic import Field

from ..authz import OPERATE

INTEGRATION_NAME = "openbao"
METADATA_SCHEMA = "1"

# Only metadata reservation and metadata status are implemented. Every other
# credential lifecycle action remains an explicit unsupported result; no
# executor action or HTTP endpoint is invented for it.
SUPPORTED_ACTIONS: tuple[str, ...] = ("metadata_reserve", "metadata_status")
UNSUPPORTED_ACTIONS: Mapping[str, str] = MappingProxyType(
    {
        "issue": (
            "Not implemented in this source change. The eventual action must use a "
            "separately reviewed trusted-executor issuer action and the #18 "
            "credential_* contract; no issuer endpoint is assumed here."
        ),
        "deliver": (
            "Not implemented. Delivery to ESO/ExternalSecret or another consumer "
            "requires the reviewed #725/#1030 consumer contract; no delivery "
            "endpoint is assumed here."
        ),
        "rotate": (
            "Not implemented. Rotation requires the #18 credential_apply contract, "
            "a reviewed trusted-executor action and separate cutover approval."
        ),
        "revoke": (
            "Not implemented. Revocation requires a separate reviewed executor "
            "action, an independent break-glass path and explicit scope validation."
        ),
        "policy_authoring": (
            "Not accepted. Arbitrary ACL or policy text is deliberately excluded; "
            "policy authoring stays inside the guarded executor."
        ),
        "role_authoring": (
            "Not accepted. OpenBao or Kubernetes role authoring stays inside the "
            "guarded executor; this interface only reserves KVv2 metadata."
        ),
        "secret_read": ("Not implemented. No raw KV data path or stored value is exposed to MCP."),
        "secret_write": (
            "Not implemented. The owner enters external values in the OpenBao UI; "
            "no secret value is accepted as a tool argument."
        ),
    }
)

_CUSTOM_SCHEMA = "kule-schema"
_CUSTOM_PROFILE = "kule-profile"
_CUSTOM_REQUIRED_KEYS = "kule-required-keys"
_CUSTOM_PROVIDER_SCOPE = "kule-provider-scope"
_CUSTOM_CONSUMER = "kule-consumer"
_CUSTOM_EXPIRES_AT = "kule-expires-at"
_RESERVATION_KEYS = (
    _CUSTOM_SCHEMA,
    _CUSTOM_PROFILE,
    _CUSTOM_REQUIRED_KEYS,
    _CUSTOM_PROVIDER_SCOPE,
    _CUSTOM_CONSUMER,
    _CUSTOM_EXPIRES_AT,
)

_MAX_PATH = 200
_MAX_PREFIX = 200
_MAX_KEYS = 64
_MAX_CONFIG_KEYS = 16
_MAX_CUSTOM_METADATA = 64
_MAX_CUSTOM_VALUE = 2048
_MAX_TEXT = 128

_NAME = re.compile(r"[a-z][a-z0-9_-]{1,63}")
_MOUNT = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_SEGMENT = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
_SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_CONSUMER = re.compile(r"[a-z][a-z0-9._-]{1,63}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class OpenBaoError(RuntimeError):
    """Base error for onboarding and metadata status."""


class OpenBaoConfigError(OpenBaoError):
    """The injected profile or UI template is not safe to use."""


class OpenBaoInputError(ValueError):
    """A caller supplied a target outside the reviewed profile."""


class OpenBaoExecutorError(OpenBaoError):
    """The trusted executor returned an unusable result."""


class OpenBaoExecutor(Protocol):
    """Narrow contract implemented by the reviewed trusted executor.

    The adapter maps these methods to the native KVv2 metadata API only:
    ``GET /v1/{mount}/metadata/{path}`` and
    ``POST /v1/{mount}/metadata/{path}`` with ``custom_metadata``. It must not
    read or write ``/data/`` paths, accept a token or policy body, or expose a
    secret value.
    """

    async def read_kv_metadata(self, *, mount: str, path: str) -> Mapping[str, Any] | None: ...

    async def reserve_kv_metadata(
        self, *, mount: str, path: str, custom_metadata: Mapping[str, str]
    ) -> None: ...


@dataclass(frozen=True)
class OpenBaoProfile:
    """One reviewed onboarding profile and its exact path prefix/consumers."""

    name: str
    path_prefix: str
    consumers: tuple[str, ...]
    mount: str = "kv"
    required_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _NAME.fullmatch(self.name):
            raise OpenBaoConfigError("profile name must match ^[a-z][a-z0-9_-]{1,63}$")
        if not isinstance(self.mount, str) or not _MOUNT.fullmatch(self.mount):
            raise OpenBaoConfigError("profile mount must be a short KV mount name")
        prefix = _validate_prefix(self.path_prefix)
        if isinstance(self.consumers, (str, bytes)) or not isinstance(self.consumers, Sequence):
            raise OpenBaoConfigError("profile consumers must be a sequence of names")
        consumers = tuple(self.consumers)
        if not consumers:
            raise OpenBaoConfigError("profile must declare at least one consumer")
        for consumer in consumers:
            _validate_consumer_name(consumer)
        if len(set(consumers)) != len(consumers):
            raise OpenBaoConfigError("profile consumers must be unique")
        if isinstance(self.required_keys, (str, bytes)) or not isinstance(
            self.required_keys, Sequence
        ):
            raise OpenBaoConfigError("profile required_keys must be a sequence of key names")
        keys = tuple(self.required_keys)
        if len(keys) > _MAX_CONFIG_KEYS:
            raise OpenBaoConfigError("profile declares too many required keys")
        for key in keys:
            try:
                _validate_key_name(key)
            except OpenBaoInputError as exc:
                raise OpenBaoConfigError(str(exc)) from None
        if len(set(keys)) != len(keys):
            raise OpenBaoConfigError("profile required keys must be unique")
        object.__setattr__(self, "path_prefix", prefix)
        object.__setattr__(self, "consumers", consumers)
        object.__setattr__(self, "required_keys", keys)

    def allows_path(self, path: str) -> bool:
        # The prefix itself is a folder-like target, not one exact secret path.
        return path.startswith(self.path_prefix + "/")


@dataclass(frozen=True)
class OpenBaoConfig:
    """Reviewed profiles plus the exact, pre-validated OpenBao UI template."""

    profiles: tuple[OpenBaoProfile, ...]
    ui_secret_url_template: str
    max_required_keys: int = 16

    def __post_init__(self) -> None:
        if isinstance(self.profiles, (str, bytes)) or not isinstance(self.profiles, Sequence):
            raise OpenBaoConfigError("profiles must be a sequence of OpenBaoProfile")
        profiles = tuple(self.profiles)
        if not profiles:
            raise OpenBaoConfigError("at least one OpenBao profile is required")
        if not all(isinstance(profile, OpenBaoProfile) for profile in profiles):
            raise OpenBaoConfigError("profiles must contain only OpenBaoProfile values")
        names = [profile.name for profile in profiles]
        if len(set(names)) != len(names):
            raise OpenBaoConfigError("OpenBao profile names must be unique")
        _validate_ui_template(self.ui_secret_url_template)
        if (
            isinstance(self.max_required_keys, bool)
            or not isinstance(self.max_required_keys, int)
            or not 1 <= self.max_required_keys <= _MAX_CONFIG_KEYS
        ):
            raise OpenBaoConfigError("max_required_keys must be an integer from 1 to 16")
        object.__setattr__(self, "profiles", profiles)

    def profile(self, name: str) -> OpenBaoProfile:
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise OpenBaoInputError("profile must match ^[a-z][a-z0-9_-]{1,63}$")
        for profile in self.profiles:
            if profile.name == name:
                return profile
        raise OpenBaoInputError("profile is not approved for OpenBao onboarding")


@dataclass(frozen=True)
class OnboardingRequest:
    profile: str
    path: str
    required_keys: tuple[str, ...]
    provider_scope: str
    consumer: str
    expires_at: str | None = None


@dataclass(frozen=True)
class MetadataView:
    current_version: int
    custom_metadata: Mapping[str, str]
    created_time: str | None = None
    updated_time: str | None = None
    max_versions: int | None = None
    cas_required: bool | None = None
    delete_version_after: str | None = None


def _validate_prefix(raw: object) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_PREFIX:
        raise OpenBaoConfigError("path_prefix must be a non-empty bounded string")
    if raw != raw.strip() or raw.startswith("/") or raw.endswith("/") or "//" in raw:
        raise OpenBaoConfigError("path_prefix must be canonical without leading/trailing slash")
    segments = raw.split("/")
    if any(part in ("", ".", "..") or not _SEGMENT.fullmatch(part) for part in segments):
        raise OpenBaoConfigError("path_prefix contains an unsafe segment")
    return raw


def _validate_path(raw: object, profile: OpenBaoProfile) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_PATH:
        raise OpenBaoInputError("path must be a non-empty bounded string")
    if raw != raw.strip() or raw.startswith("/") or raw.endswith("/") or "//" in raw:
        raise OpenBaoInputError("path must be canonical without leading/trailing slash")
    segments = raw.split("/")
    if any(part in ("", ".", "..") or not _SEGMENT.fullmatch(part) for part in segments):
        raise OpenBaoInputError("path contains an unsafe segment")
    if not profile.allows_path(raw):
        raise OpenBaoInputError("path is outside the approved profile prefix")
    return raw


def _validate_key_name(raw: object) -> str:
    if not isinstance(raw, str) or not _KEY.fullmatch(raw):
        raise OpenBaoInputError("required keys must match ^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
    return raw


def _validate_keys(
    raw: Sequence[str], profile: OpenBaoProfile, config: OpenBaoConfig
) -> tuple[str, ...]:
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        raise OpenBaoInputError("required_keys must be a list of key names")
    keys = tuple(raw)
    if not keys:
        raise OpenBaoInputError("required_keys must not be empty")
    if len(keys) > config.max_required_keys:
        raise OpenBaoInputError("too many required keys for this profile")
    for key in keys:
        _validate_key_name(key)
    if len(set(keys)) != len(keys):
        raise OpenBaoInputError("required keys must be unique")
    if profile.required_keys and set(keys) != set(profile.required_keys):
        raise OpenBaoInputError("required keys differ from the approved profile template")
    return keys


def _validate_scope(raw: object) -> str:
    if not isinstance(raw, str) or not _SCOPE.fullmatch(raw):
        raise OpenBaoInputError("provider_scope must be a short identifier")
    if raw != raw.strip() or ".." in raw or "//" in raw or raw.startswith("/") or raw.endswith("/"):
        raise OpenBaoInputError("provider_scope must be canonical")
    if "*" in raw or any(ord(char) < 32 for char in raw):
        raise OpenBaoInputError("provider_scope must not contain wildcards or control characters")
    return raw


def _validate_consumer_name(raw: object) -> str:
    if not isinstance(raw, str) or not _CONSUMER.fullmatch(raw):
        raise OpenBaoConfigError("consumer must match ^[a-z][a-z0-9._-]{1,63}$")
    return raw


def _validate_consumer(raw: object, profile: OpenBaoProfile) -> str:
    if not isinstance(raw, str) or not _CONSUMER.fullmatch(raw):
        raise OpenBaoInputError("consumer must match ^[a-z][a-z0-9._-]{1,63}$")
    if raw not in profile.consumers:
        raise OpenBaoInputError("consumer is not approved for this profile")
    return raw


def _validate_expiry(raw: object) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str) or not _DATE.fullmatch(raw):
        raise OpenBaoInputError("expires_at must be a UTC date formatted YYYY-MM-DD")
    try:
        expires = date.fromisoformat(raw)
    except ValueError:
        raise OpenBaoInputError("expires_at is not a real date") from None
    if expires < datetime.now(UTC).date():
        raise OpenBaoInputError("expires_at must not be in the past")
    return raw


def _validate_ui_template(raw: object) -> str:
    if not isinstance(raw, str) or not raw:
        raise OpenBaoConfigError("ui_secret_url_template is required; no URL is guessed")
    if "{mount}" not in raw or "{path}" not in raw:
        raise OpenBaoConfigError("ui_secret_url_template must contain {mount} and {path}")
    try:
        sample = raw.format(mount="kv", path="example/path")
    except (KeyError, IndexError, ValueError):
        raise OpenBaoConfigError("ui_secret_url_template contains an unknown placeholder") from None
    if "{" in sample or "}" in sample:
        raise OpenBaoConfigError("ui_secret_url_template contains an unknown placeholder")
    try:
        parsed = urlsplit(sample)
        port = parsed.port
    except ValueError:
        raise OpenBaoConfigError("ui_secret_url_template must produce a valid HTTPS URL") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise OpenBaoConfigError(
            "ui_secret_url_template must produce an HTTPS URL without userinfo, query or fragment"
        )
    return raw


def _ui_url(config: OpenBaoConfig, profile: OpenBaoProfile, path: str) -> str:
    return config.ui_secret_url_template.format(
        mount=quote(profile.mount, safe=""),
        path=quote(path, safe="/"),
    )


def _bounded_text(raw: object, field: str, *, max_length: int = _MAX_TEXT) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > max_length:
        raise OpenBaoExecutorError(f"trusted executor returned an invalid {field}")
    if any(ord(char) < 32 for char in raw):
        raise OpenBaoExecutorError(f"trusted executor returned a control character in {field}")
    return raw


def _optional_text(raw: object, field: str) -> str | None:
    if raw is None or raw == "":
        return None
    return _bounded_text(raw, field, max_length=64)


def _metadata_int(raw: object, field: str, default: int | None = None) -> int | None:
    if raw is None:
        return default
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise OpenBaoExecutorError(f"trusted executor returned an invalid {field}")
    return raw


def _unwrap_metadata(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    """Accept a direct metadata object or the native ``{"data": {...}}`` envelope."""
    nested = raw.get("data")
    if isinstance(nested, Mapping) and (
        "current_version" in nested or "custom_metadata" in nested or "created_time" in nested
    ):
        return nested
    return raw


def _parse_metadata(raw: Mapping[str, Any] | None) -> MetadataView | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise OpenBaoExecutorError("trusted executor returned non-mapping metadata")
    data = _unwrap_metadata(raw)
    current_version = _metadata_int(data.get("current_version"), "current_version")
    if current_version is None:
        raise OpenBaoExecutorError("trusted executor returned no current_version")

    custom_raw = data.get("custom_metadata")
    if custom_raw is None:
        custom: dict[str, str] = {}
    elif isinstance(custom_raw, Mapping):
        custom = {}
        for key, value in custom_raw.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise OpenBaoExecutorError("trusted executor returned non-string custom metadata")
            if not key or len(key) > _MAX_TEXT or len(value) > _MAX_CUSTOM_VALUE:
                raise OpenBaoExecutorError("trusted executor returned oversized custom metadata")
            if any(ord(char) < 32 for char in key):
                raise OpenBaoExecutorError(
                    "trusted executor returned a control character in metadata"
                )
            custom[key] = value
        if len(custom) > _MAX_CUSTOM_METADATA:
            raise OpenBaoExecutorError("trusted executor returned too many custom metadata entries")
    else:
        raise OpenBaoExecutorError("trusted executor returned invalid custom_metadata")

    cas_required = data.get("cas_required")
    if cas_required is not None and not isinstance(cas_required, bool):
        raise OpenBaoExecutorError("trusted executor returned an invalid cas_required")

    return MetadataView(
        current_version=current_version,
        custom_metadata=MappingProxyType(custom),
        created_time=_optional_text(data.get("created_time"), "created_time"),
        updated_time=_optional_text(data.get("updated_time"), "updated_time"),
        max_versions=_metadata_int(data.get("max_versions"), "max_versions"),
        cas_required=cas_required,
        delete_version_after=_optional_text(
            data.get("delete_version_after"), "delete_version_after"
        ),
    )


def _reservation_metadata(request: OnboardingRequest) -> dict[str, str]:
    metadata = {
        _CUSTOM_SCHEMA: METADATA_SCHEMA,
        _CUSTOM_PROFILE: request.profile,
        _CUSTOM_REQUIRED_KEYS: ",".join(request.required_keys),
        _CUSTOM_PROVIDER_SCOPE: request.provider_scope,
        _CUSTOM_CONSUMER: request.consumer,
    }
    if request.expires_at is not None:
        metadata[_CUSTOM_EXPIRES_AT] = request.expires_at
    return metadata


def _merge_custom_metadata(
    existing: Mapping[str, str], reserved: Mapping[str, str]
) -> dict[str, str]:
    merged = dict(existing)
    # The native metadata POST fully overwrites custom_metadata. Preserve
    # unrelated operator keys instead of replacing them with only Kule's fields.
    merged.update(reserved)
    if len(merged) > _MAX_CUSTOM_METADATA:
        raise OpenBaoExecutorError("existing custom metadata is too large to merge safely")
    for key, value in merged.items():
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or not key
            or len(key) > _MAX_TEXT
            or len(value) > _MAX_CUSTOM_VALUE
        ):
            raise OpenBaoExecutorError("existing custom metadata is not bounded string data")
    return merged


def _parse_reservation(custom: Mapping[str, str]) -> dict[str, Any] | None:
    if not any(key in custom for key in _RESERVATION_KEYS):
        return None
    profile = custom.get(_CUSTOM_PROFILE)
    keys_raw = custom.get(_CUSTOM_REQUIRED_KEYS)
    scope = custom.get(_CUSTOM_PROVIDER_SCOPE)
    consumer = custom.get(_CUSTOM_CONSUMER)
    schema = custom.get(_CUSTOM_SCHEMA)
    expires = custom.get(_CUSTOM_EXPIRES_AT)
    if schema != METADATA_SCHEMA:
        return None
    if not isinstance(profile, str) or not _NAME.fullmatch(profile):
        return None
    if not isinstance(scope, str) or not _SCOPE.fullmatch(scope):
        return None
    if not isinstance(consumer, str) or not _CONSUMER.fullmatch(consumer):
        return None
    if not isinstance(keys_raw, str):
        return None
    keys = tuple(keys_raw.split(",")) if keys_raw else ()
    if not keys or len(keys) > _MAX_KEYS:
        return None
    for key in keys:
        if not _KEY.fullmatch(key):
            return None
    if len(set(keys)) != len(keys):
        return None
    if expires is not None:
        if not isinstance(expires, str) or not _DATE.fullmatch(expires):
            return None
        try:
            date.fromisoformat(expires)
        except ValueError:
            return None
    return {
        "profile": profile,
        "required_keys": list(keys),
        "provider_scope": scope,
        "consumer": consumer,
        "expires_at": expires,
    }


def _reservation_matches_request(
    reservation: Mapping[str, Any], request: OnboardingRequest
) -> bool:
    return (
        reservation.get("profile") == request.profile
        and set(reservation.get("required_keys") or ()) == set(request.required_keys)
        and reservation.get("provider_scope") == request.provider_scope
        and reservation.get("consumer") == request.consumer
        and reservation.get("expires_at") == request.expires_at
    )


def _metadata_summary(metadata: MetadataView | None) -> dict[str, Any] | None:
    if metadata is None:
        return None
    # Only recognized reservation keys are named. Unknown custom metadata can
    # contain unrelated operational data and is never echoed by this module.
    return {
        "exists": True,
        "current_version": metadata.current_version,
        "created_time": metadata.created_time,
        "updated_time": metadata.updated_time,
        "max_versions": metadata.max_versions,
        "cas_required": metadata.cas_required,
        "delete_version_after": metadata.delete_version_after,
        "custom_metadata_key_count": len(metadata.custom_metadata),
        "recognized_metadata_keys": sorted(
            key for key in metadata.custom_metadata if key in _RESERVATION_KEYS
        ),
    }


def _instructions(
    *, status: str, profile: OpenBaoProfile, path: str, keys: Sequence[str]
) -> list[str]:
    if status == "value_present_unverified":
        return [
            f"A data version already exists at {profile.mount}/{path}; no metadata was changed.",
            "Do not replace an existing value without a separate reviewed cutover.",
            "Metadata/version presence does not prove the stored value or provider permissions.",
        ]
    if status == "absent":
        return [
            f"No KVv2 metadata reservation exists at {profile.mount}/{path}.",
            "Use openbao_onboarding_prepare with an approved profile before entering a value.",
        ]
    if status == "metadata_only":
        return [
            f"KVv2 metadata exists at {profile.mount}/{path} "
            "but has no recognized Kule reservation.",
            "Inspect the existing path and do not overwrite it without a separate reviewed change.",
        ]
    names = ", ".join(keys) if keys else "the approved key names"
    return [
        "Open the exact OpenBao UI URL in a private browser session.",
        f"Enter only these key names: {names}.",
        "Do not paste values into chat, MCP arguments, Git, CI, logs or a ticket.",
        "A metadata reservation is not proof that the value or provider permissions are correct.",
    ]


def _base_result(
    *,
    config: OpenBaoConfig,
    profile: OpenBaoProfile,
    path: str,
    status: str,
    metadata: MetadataView | None,
    reservation_written: bool,
    keys: Sequence[str],
    request: OnboardingRequest | None = None,
) -> dict[str, Any]:
    reservation = _parse_reservation(metadata.custom_metadata) if metadata else None
    expires_at = reservation["expires_at"] if reservation else None
    expired = False
    if expires_at:
        expired = date.fromisoformat(expires_at) < datetime.now(UTC).date()
    return {
        "status": status,
        "profile": profile.name,
        "mount": profile.mount,
        "path": path,
        "required_keys": list(keys),
        "provider_scope": request.provider_scope if request else None,
        "consumer": request.consumer if request else (reservation or {}).get("consumer"),
        "expires_at": request.expires_at if request else expires_at,
        "expired": expired,
        "ui_url": _ui_url(config, profile, path),
        "instructions": _instructions(status=status, profile=profile, path=path, keys=keys),
        "reservation_written": reservation_written,
        "reservation": reservation,
        "reservation_matches_profile": (
            reservation["profile"] == profile.name if reservation else None
        ),
        "metadata": _metadata_summary(metadata),
        "value_state": (
            "absent"
            if metadata is None
            else "awaiting_value"
            if metadata.current_version == 0
            else "value_present_unverified"
        ),
        "value_read": False,
        "verification": "not_performed",
        "supported_actions": list(SUPPORTED_ACTIONS),
        "unsupported_actions": dict(UNSUPPORTED_ACTIONS),
    }


async def prepare_onboarding(
    executor: OpenBaoExecutor,
    config: OpenBaoConfig,
    *,
    profile: str,
    path: str,
    required_keys: Sequence[str],
    provider_scope: str,
    consumer: str,
    expires_at: str | None = None,
) -> dict[str, Any]:
    """Reserve an empty KVv2 metadata record and return owner input instructions.

    The operation never reads or writes a secret value. If the exact path already
    has a data version, it returns ``value_present_unverified`` and makes no
    metadata write, so an existing consumer is not silently changed.
    """
    profile_spec = config.profile(profile)
    exact_path = _validate_path(path, profile_spec)
    keys = _validate_keys(required_keys, profile_spec, config)
    scope = _validate_scope(provider_scope)
    approved_consumer = _validate_consumer(consumer, profile_spec)
    expiry = _validate_expiry(expires_at)
    request = OnboardingRequest(
        profile=profile_spec.name,
        path=exact_path,
        required_keys=keys,
        provider_scope=scope,
        consumer=approved_consumer,
        expires_at=expiry,
    )

    before = _parse_metadata(
        await executor.read_kv_metadata(mount=profile_spec.mount, path=exact_path)
    )
    if before is not None and before.current_version > 0:
        return _base_result(
            config=config,
            profile=profile_spec,
            path=exact_path,
            status="value_present_unverified",
            metadata=before,
            reservation_written=False,
            keys=keys,
            request=request,
        )

    if before is not None:
        existing_reservation = _parse_reservation(before.custom_metadata)
        if existing_reservation is not None and not _reservation_matches_request(
            existing_reservation, request
        ):
            raise OpenBaoInputError(
                "path already has a different Kule metadata reservation; "
                "use a separate reviewed change"
            )

    reserved = _reservation_metadata(request)
    merged = _merge_custom_metadata(before.custom_metadata if before else {}, reserved)
    await executor.reserve_kv_metadata(
        mount=profile_spec.mount,
        path=exact_path,
        custom_metadata=merged,
    )

    after = _parse_metadata(
        await executor.read_kv_metadata(mount=profile_spec.mount, path=exact_path)
    )
    if after is None:
        raise OpenBaoExecutorError(
            "metadata reservation was written but the trusted executor cannot read it back"
        )
    status = "value_present_unverified" if after.current_version > 0 else "awaiting_value"
    return _base_result(
        config=config,
        profile=profile_spec,
        path=exact_path,
        status=status,
        metadata=after,
        reservation_written=True,
        keys=keys,
        request=request,
    )


async def read_status(
    executor: OpenBaoExecutor,
    config: OpenBaoConfig,
    *,
    profile: str,
    path: str,
) -> dict[str, Any]:
    """Return KVv2 metadata and reservation state for one approved exact path."""
    profile_spec = config.profile(profile)
    exact_path = _validate_path(path, profile_spec)
    metadata = _parse_metadata(
        await executor.read_kv_metadata(mount=profile_spec.mount, path=exact_path)
    )
    reservation = _parse_reservation(metadata.custom_metadata) if metadata else None
    keys = tuple(reservation["required_keys"]) if reservation else ()
    if metadata is None:
        status = "absent"
    elif metadata.current_version > 0:
        status = "value_present_unverified"
    elif reservation is not None:
        status = "awaiting_value"
    else:
        status = "metadata_only"
    return _base_result(
        config=config,
        profile=profile_spec,
        path=exact_path,
        status=status,
        metadata=metadata,
        reservation_written=False,
        keys=keys,
        request=None,
    )


def register(mcp: FastMCP, *, executor: OpenBaoExecutor, config: OpenBaoConfig) -> None:
    """Register the two operator-only tools; wiring is a separate reviewed change.

    Follow-up wiring: call this from ``server.build_server`` only after the
    trusted executor exposes the reviewed metadata actions and #23/#24 settle
    the shared registry. This change intentionally does not import or call it.
    """
    annotations_write = {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    annotations_read = {"readOnlyHint": True, "openWorldHint": False}

    @mcp.tool(tags={OPERATE}, annotations=annotations_write)
    async def openbao_onboarding_prepare(
        profile: Annotated[str, Field(description="approved onboarding profile name")],
        path: Annotated[str, Field(description="exact KVv2 path under the profile prefix")],
        required_keys: Annotated[
            list[str], Field(description="exact key names the owner will enter in OpenBao UI")
        ],
        provider_scope: Annotated[
            str, Field(description="intended provider scope, e.g. github:yesvus/developer")
        ],
        consumer: Annotated[str, Field(description="approved consumer profile name")],
        expires_at: Annotated[
            str | None, Field(description="optional UTC date formatted YYYY-MM-DD")
        ] = None,
    ) -> dict:
        """Reserve an empty KVv2 metadata record and return the owner input URL.

        No secret value is accepted. The owner enters values only in the OpenBao UI.
        """
        return await prepare_onboarding(
            executor,
            config,
            profile=profile,
            path=path,
            required_keys=required_keys,
            provider_scope=provider_scope,
            consumer=consumer,
            expires_at=expires_at,
        )

    @mcp.tool(tags={OPERATE}, annotations=annotations_read)
    async def openbao_status(
        profile: Annotated[str, Field(description="approved onboarding profile name")],
        path: Annotated[str, Field(description="exact KVv2 path under the profile prefix")],
    ) -> dict:
        """Show KVv2 metadata and reservation state; never reads a value."""
        return await read_status(executor, config, profile=profile, path=path)
