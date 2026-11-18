"""Read-only OnWatch quota telemetry for worker model selection.

This module intentionally talks to the existing authenticated OnWatch
Prometheus endpoint. It does not scrape in the background, store quota data,
call provider APIs, or accept credentials as tool arguments. The module is
source-only until ``register`` is added to the Kule server registry.
"""

from __future__ import annotations

import asyncio
import math
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import httpx2
from fastmcp import FastMCP
from pydantic import Field

from ..authz import READ

QUOTA_UTILIZATION = "onwatch_quota_utilization_percent"
QUOTA_RESET = "onwatch_quota_reset_timestamp_seconds"
AGENT_HEALTHY = "onwatch_agent_healthy"
AGENT_LAST_CYCLE_AGE = "onwatch_agent_last_cycle_age_seconds"
ACCOUNT_INFO = "onwatch_account_info"

# Upstream documents a reset timestamp more than 15 minutes in the past as a
# missed reset (OnwatchQuotaResetMissed). Keep the same grace period rather
# than treating polling health as proof that quota data is current.
RESET_GRACE_SECONDS = 900
MAX_BODY_BYTES = 512 * 1024
MAX_SERIES = 5000
MAX_PROVIDERS = 100
MAX_WINDOWS = 300
MAX_TEXT = 80

_LABEL_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
_PROVIDER = re.compile(r"[a-z0-9_]{1,64}")
_SAMPLE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:\{(?P<labels>.*)\})?"
    r"\s+(?P<value>\S+)(?:\s+\S+)?$"
)
_INTERESTING = {
    QUOTA_UTILIZATION,
    QUOTA_RESET,
    AGENT_HEALTHY,
    AGENT_LAST_CYCLE_AGE,
    ACCOUNT_INFO,
}


def _base_url() -> str | None:
    """Return one fixed origin; plain HTTP is only accepted on loopback."""
    raw = os.environ.get("KULE_ONWATCH_URL", "")
    if not raw:
        return None
    if raw != raw.strip() or "?" in raw or "#" in raw:
        raise ValueError("KULE_ONWATCH_URL must be a fixed origin")
    base = raw.rstrip("/")
    try:
        parsed = urlsplit(base)
        port = parsed.port
    except ValueError:
        raise ValueError("KULE_ONWATCH_URL must be a fixed origin") from None
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("KULE_ONWATCH_URL must be a fixed origin")
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    ):
        raise ValueError("KULE_ONWATCH_URL must use HTTPS, except on loopback")
    return base


def _auth_headers() -> dict[str, str]:
    """Read the metrics token from its mounted file; never log its value."""
    raw_path = os.environ.get("KULE_ONWATCH_TOKEN_FILE", "")
    if not raw_path:
        return {}
    try:
        token = Path(raw_path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        raise RuntimeError("OnWatch metrics token file is not readable") from None
    if not token:
        raise RuntimeError("OnWatch metrics token file is empty")
    return {"Authorization": f"Bearer {token}"}


def _unescape(value: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        index += 1
        if index >= len(value):
            raise ValueError("trailing label escape")
        escaped = value[index]
        if escaped == "n":
            out.append("\n")
        elif escaped in {'"', "\\"}:
            out.append(escaped)
        else:
            raise ValueError("invalid label escape")
        index += 1
    return "".join(out)


def _parse_labels(raw: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    index = 0
    while index < len(raw):
        while index < len(raw) and raw[index] in " \t,":
            index += 1
        if index >= len(raw):
            break
        match = _LABEL_NAME.match(raw, index)
        if not match:
            raise ValueError("invalid label name")
        name = match.group()
        index = match.end()
        while index < len(raw) and raw[index] in " \t":
            index += 1
        if index >= len(raw) or raw[index] != "=":
            raise ValueError("missing label equals")
        index += 1
        while index < len(raw) and raw[index] in " \t":
            index += 1
        if index >= len(raw) or raw[index] != '"':
            raise ValueError("missing label quote")
        index += 1
        value: list[str] = []
        while index < len(raw):
            if raw[index] == '"':
                index += 1
                break
            if raw[index] == "\\":
                value.append(raw[index])
                index += 1
                if index >= len(raw):
                    raise ValueError("trailing label escape")
            value.append(raw[index])
            index += 1
        else:
            raise ValueError("unterminated label")
        if name in labels:
            raise ValueError("duplicate label")
        labels[name] = _unescape("".join(value))
    return labels


def parse_metrics(text: str) -> list[tuple[str, dict[str, str], float | None]]:
    """Parse bounded Prometheus text exposition into samples.

    Comments, HELP/TYPE lines and standard runtime metrics are ignored. A
    malformed quota sample fails the whole read rather than returning a
    silently incomplete quota view.
    """
    samples: list[tuple[str, dict[str, str], float | None]] = []
    for line_number, line in enumerate(text.split("\n"), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _SAMPLE.match(line)
        if not match:
            raise ValueError(f"invalid metric line {line_number}")
        name = match.group("name")
        try:
            labels = _parse_labels(match.group("labels") or "")
            raw_value = float(match.group("value"))
        except ValueError:
            raise ValueError(f"invalid metric line {line_number}") from None
        if name not in _INTERESTING:
            continue
        value = raw_value if math.isfinite(raw_value) else None
        samples.append((name, labels, value))
        if len(samples) > MAX_SERIES:
            raise ValueError("OnWatch metrics contain too many quota series")
    return samples


def _text(value: object, *, truncated: list[bool]) -> str:
    clean = "".join(
        char if char.isprintable() and char not in "\r\n\t" else " " for char in str(value)
    )
    clean = " ".join(clean.split())
    if len(clean) > MAX_TEXT:
        truncated[0] = True
        clean = clean[:MAX_TEXT]
    return clean


def _iso(timestamp: float | None) -> str | None:
    if timestamp is None or timestamp <= 0:
        return None
    try:
        return datetime.fromtimestamp(timestamp, UTC).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None


def _reset_state(
    raw_value: float | None,
    *,
    present: bool,
    now: float,
    grace_seconds: float,
) -> tuple[str | None, str, int | None]:
    if not present:
        return None, "not_scheduled", None
    if raw_value is None:
        return None, "unknown", None
    reset_at = _iso(raw_value)
    if reset_at is None:
        return None, "unknown", None
    remaining = round(raw_value - now)
    if raw_value < now - grace_seconds:
        return reset_at, "passed", remaining
    if raw_value <= now:
        return reset_at, "due", remaining
    return reset_at, "scheduled", remaining


def _overall_status(statuses) -> str:
    statuses = list(statuses)
    if not statuses:
        return "unknown"
    if all(status == "fresh" for status in statuses):
        return "fresh"
    if all(status == "stale" for status in statuses):
        return "stale"
    if any(status == "fresh" for status in statuses):
        return "degraded"
    return "unknown"


def _useful_alias(
    aliases: dict[tuple[str, str], str], provider: str, account_id: str
) -> str | None:
    alias = aliases.get((provider, account_id))
    if not alias or alias in {account_id, "default"}:
        return None
    # Account names are operator-provided and may themselves contain the
    # numeric account ID. Omit rather than returning a partial identifier.
    normalized_account = re.sub(r"[^0-9a-z]", "", account_id.casefold())
    normalized_alias = re.sub(r"[^0-9a-z]", "", alias.casefold())
    if normalized_account and normalized_account in normalized_alias:
        return None
    return alias


def _alias_map(
    samples: list[tuple[str, dict[str, str], float | None]],
) -> dict[tuple[str, str], str]:
    aliases: dict[tuple[str, str], str] = {}
    for name, labels, value in samples:
        if name != ACCOUNT_INFO or value is None:
            continue
        provider = labels.get("provider", "")
        account = labels.get("account_id", "")
        alias = labels.get("account_name", "")
        if provider and account and alias:
            aliases[(provider, account)] = alias
    return aliases


def summarize(
    samples: list[tuple[str, dict[str, str], float | None]],
    *,
    now: float | None = None,
    reset_grace_seconds: float = RESET_GRACE_SECONDS,
    provider: str | None = None,
) -> dict:
    """Normalize OnWatch series without exposing raw account IDs or tokens."""
    now = time.time() if now is None else now
    truncated = [False]
    aliases = _alias_map(samples)

    util: dict[tuple[str, str, str], float | None] = {}
    reset: dict[tuple[str, str, str], float | None] = {}
    health: dict[tuple[str, str], float | None] = {}
    age: dict[tuple[str, str], float | None] = {}
    provider_accounts: set[tuple[str, str]] = set()

    for name, labels, value in samples:
        raw_provider = labels.get("provider", "")
        raw_account = labels.get("account_id", "")
        if not raw_provider or not raw_account:
            continue
        provider_name = _text(raw_provider, truncated=truncated)
        if not provider_name:
            continue
        account_id = str(raw_account)
        provider_accounts.add((provider_name, account_id))
        if name == QUOTA_UTILIZATION:
            window = _text(labels.get("quota_type", ""), truncated=truncated)
            if window:
                util[(provider_name, account_id, window)] = value
        elif name == QUOTA_RESET:
            window = _text(labels.get("quota_type", ""), truncated=truncated)
            if window:
                reset[(provider_name, account_id, window)] = value
        elif name == AGENT_HEALTHY:
            health[(provider_name, account_id)] = value
        elif name == AGENT_LAST_CYCLE_AGE:
            age[(provider_name, account_id)] = value

    if provider is not None:
        provider_accounts = {key for key in provider_accounts if key[0] == provider}

    accounts_by_provider: dict[str, list[str]] = {}
    for provider_name, account_id in provider_accounts:
        accounts_by_provider.setdefault(provider_name, []).append(account_id)

    account_labels: dict[tuple[str, str], str | None] = {}
    for provider_name, account_ids in accounts_by_provider.items():
        unnamed = sorted(
            account_id
            for account_id in account_ids
            if account_id != "default" and _useful_alias(aliases, provider_name, account_id) is None
        )
        positions = {account_id: index + 1 for index, account_id in enumerate(unnamed)}
        for account_id in account_ids:
            alias = _useful_alias(aliases, provider_name, account_id)
            if alias:
                account_labels[(provider_name, account_id)] = _text(alias, truncated=truncated)
            elif account_id == "default":
                account_labels[(provider_name, account_id)] = None
            else:
                account_labels[(provider_name, account_id)] = f"account-{positions[account_id]}"

    provider_rows = []
    for provider_name in sorted(accounts_by_provider):
        for account_id in sorted(accounts_by_provider[provider_name]):
            key = (provider_name, account_id)
            health_value = health.get(key)
            health_status = (
                "fresh" if health_value == 1 else "stale" if health_value == 0 else "unknown"
            )
            last_age = age.get(key)
            if last_age is not None and (last_age < 0 or not math.isfinite(last_age)):
                last_age = None

            window_names = sorted(
                {
                    window
                    for row_provider, row_account, window in [*util, *reset]
                    if row_provider == provider_name and row_account == account_id
                }
            )
            windows = []
            window_statuses = []
            for window in window_names:
                window_key = (provider_name, account_id, window)
                utilization = util.get(window_key)
                reset_present = window_key in reset
                reset_raw = reset.get(window_key)
                reset_at, reset_status, reset_in = _reset_state(
                    reset_raw,
                    present=reset_present,
                    now=now,
                    grace_seconds=reset_grace_seconds,
                )
                reasons: list[str] = []
                statuses: set[str] = set()
                valid_utilization = utilization is not None and 0 <= utilization <= 100

                if window_key not in util:
                    statuses.add("unknown")
                    reasons.append("utilization_missing")
                elif utilization is None:
                    statuses.add("unknown")
                    reasons.append("utilization_invalid")
                elif not valid_utilization:
                    statuses.add("unknown")
                    reasons.append("utilization_out_of_range")
                if reset_status == "unknown":
                    statuses.add("unknown")
                    reasons.append("reset_timestamp_invalid")
                if reset_status == "passed":
                    statuses.add("stale")
                    reasons.append("reset_timestamp_passed")
                if health_status == "stale":
                    statuses.add("stale")
                    reasons.append("poll_stale")
                elif health_status == "unknown":
                    statuses.add("unknown")
                    reasons.append("health_unknown")

                status = "stale" if "stale" in statuses else "unknown" if statuses else "fresh"
                window_statuses.append(status)
                remaining = (
                    round(max(0.0, min(100.0, 100 - utilization)), 1) if valid_utilization else None
                )
                windows.append(
                    {
                        "window": window,
                        "utilization_percent": utilization if valid_utilization else None,
                        "remaining_percent": remaining,
                        "reset_at": reset_at,
                        "reset_in_seconds": reset_in,
                        "reset_status": reset_status,
                        "status": status,
                        "reasons": reasons,
                    }
                )

            provider_reasons: list[str] = []
            if window_statuses:
                account_status = (
                    "stale"
                    if "stale" in window_statuses
                    else "unknown"
                    if "unknown" in window_statuses
                    else "fresh"
                )
                provider_reasons = sorted(
                    {reason for window in windows for reason in window["reasons"]}
                )
            else:
                # A healthy poll with no quota series says nothing about quota.
                # Never turn missing quota into a fresh or unlimited pool.
                account_status = "stale" if health_status == "stale" else "unknown"
                provider_reasons = ["quota_missing"]
                if health_status == "stale":
                    provider_reasons.append("poll_stale")
            provider_rows.append(
                {
                    "provider": provider_name,
                    "account": account_labels[key],
                    "status": account_status,
                    "reasons": provider_reasons,
                    "health": health_status,
                    "agent_healthy": health_value,
                    "last_cycle_age_seconds": round(last_age, 1) if last_age is not None else None,
                    "window_count": len(windows),
                    "stale_windows": sum(window["status"] == "stale" for window in windows),
                    "windows": windows,
                }
            )

    windows_total = sum(len(row["windows"]) for row in provider_rows)
    if len(provider_rows) > MAX_PROVIDERS or windows_total > MAX_WINDOWS:
        truncated[0] = True
    provider_rows = provider_rows[:MAX_PROVIDERS]
    remaining_windows = MAX_WINDOWS
    for row in provider_rows:
        row["windows"] = row["windows"][:remaining_windows]
        remaining_windows -= len(row["windows"])

    return {
        "observed_at": datetime.fromtimestamp(now, UTC).isoformat(timespec="seconds"),
        "source": "onwatch_metrics",
        "status": _overall_status(row["status"] for row in provider_rows),
        "providers": provider_rows,
        "truncated": truncated[0],
    }


async def _get_metrics(
    client: httpx2.AsyncClient,
    base_url: str,
    headers: dict[str, str],
) -> str:
    try:
        # Reject redirects before a second request could carry the token.
        async with client.stream("GET", f"{base_url}/metrics", headers=headers) as response:
            if 300 <= response.status_code < 400:
                raise RuntimeError("OnWatch metrics redirect refused")
            response.raise_for_status()
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_BODY_BYTES:
                    raise RuntimeError("OnWatch metrics response too large")
    except httpx2.HTTPError as exc:
        raise RuntimeError(f"OnWatch metrics read failed ({type(exc).__name__})") from None
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        raise RuntimeError("OnWatch metrics response is not UTF-8") from None


async def fetch_snapshot(*, timeout_seconds: float, provider: str | None = None) -> dict:
    """Fetch and normalize one on-demand snapshot; there is no background loop."""
    base_url = _base_url()
    if base_url is None:
        raise RuntimeError("OnWatch metrics are not configured")
    headers = _auth_headers()
    budget = max(0.1, min(8.0, timeout_seconds * 0.8))
    try:
        async with asyncio.timeout(budget):
            async with httpx2.AsyncClient(
                timeout=5.0, trust_env=False, follow_redirects=False
            ) as client:
                text = await _get_metrics(client, base_url, headers)
        samples = parse_metrics(text)
    except ValueError:
        raise RuntimeError("OnWatch returned invalid metrics") from None
    return summarize(samples, provider=provider)


def _provider_or_none(provider: str | None) -> str | None:
    if provider is None:
        return None
    if not _PROVIDER.fullmatch(provider):
        raise ValueError("provider must match ^[a-z0-9_]{1,64}$")
    return provider


def _health_view(snapshot: dict) -> dict:
    providers = [
        {
            "provider": row["provider"],
            "account": row["account"],
            "status": row["status"],
            "reasons": row["reasons"],
            "health": row["health"],
            "agent_healthy": row["agent_healthy"],
            "last_cycle_age_seconds": row["last_cycle_age_seconds"],
            "window_count": row["window_count"],
            "stale_windows": row["stale_windows"],
        }
        for row in snapshot["providers"]
    ]
    return {
        "observed_at": snapshot["observed_at"],
        "source": snapshot["source"],
        "status": snapshot["status"],
        "providers": providers,
        "truncated": snapshot["truncated"],
    }


def _providers_view(snapshot: dict) -> dict:
    return {
        "observed_at": snapshot["observed_at"],
        "source": snapshot["source"],
        "providers": [
            {
                "provider": row["provider"],
                "account": row["account"],
                "status": row["status"],
                "windows": [window["window"] for window in row["windows"]],
            }
            for row in snapshot["providers"]
        ],
        "truncated": snapshot["truncated"],
    }


def register(mcp: FastMCP, *, timeout_seconds: float) -> None:
    """Register the read-only quota tools when OnWatch is explicitly configured.

    Follow-up wiring: call this from ``server.build_server`` after the #23
    worker registry is settled. The default is off because ``KULE_ONWATCH_URL``
    is unset.
    """
    if _base_url() is None:
        return

    annotations = {"readOnlyHint": True, "openWorldHint": False}

    @mcp.tool(tags={READ}, annotations=annotations)
    async def onwatch_quota_status(
        provider: Annotated[
            str | None, Field(description="optional provider filter, e.g. codex")
        ] = None,
    ) -> dict:
        """Show provider/window utilization, reset time, and explicit data status."""
        selected = _provider_or_none(provider)
        return await fetch_snapshot(timeout_seconds=timeout_seconds, provider=selected)

    @mcp.tool(tags={READ}, annotations=annotations)
    async def onwatch_quota_health() -> dict:
        """Show OnWatch polling health and whether each quota view can be trusted."""
        snapshot = await fetch_snapshot(timeout_seconds=timeout_seconds)
        return _health_view(snapshot)

    @mcp.tool(tags={READ}, annotations=annotations)
    async def onwatch_providers() -> dict:
        """List available OnWatch providers, account aliases, and window names."""
        snapshot = await fetch_snapshot(timeout_seconds=timeout_seconds)
        return _providers_view(snapshot)
