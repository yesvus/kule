"""Contract tests for source-only OnWatch quota telemetry normalization."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx2
import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from operator_mcp.audit import AuditLog, verify
from operator_mcp.authz import Policy
from operator_mcp.middleware import OperatorMiddleware
from operator_mcp.tools import onwatch

NOW = 1_800_000_000.0
HOUR = 3600


def _metric(name: str, labels: dict[str, str], value: float | str) -> str:
    body = ",".join(f'{key}="{value}"' for key, value in labels.items())
    return f"{name}{{{body}}} {value}"


def _fixture() -> str:
    return "\n".join(
        [
            "# HELP onwatch_quota_utilization_percent Current quota utilization.",
            "# TYPE onwatch_quota_utilization_percent gauge",
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "codex", "quota_type": "5h", "account_id": "1"},
                42.5,
            ),
            _metric(
                onwatch.QUOTA_RESET,
                {"provider": "codex", "quota_type": "5h", "account_id": "1"},
                NOW + HOUR,
            ),
            _metric(
                onwatch.AGENT_HEALTHY,
                {"provider": "codex", "account_id": "1"},
                1,
            ),
            _metric(
                onwatch.AGENT_LAST_CYCLE_AGE,
                {"provider": "codex", "account_id": "1"},
                98,
            ),
            _metric(
                onwatch.ACCOUNT_INFO,
                {"provider": "codex", "account_id": "1", "account_name": "Work"},
                1,
            ),
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "anthropic", "quota_type": "7d", "account_id": "default"},
                90,
            ),
            _metric(
                onwatch.QUOTA_RESET,
                {"provider": "anthropic", "quota_type": "7d", "account_id": "default"},
                NOW + 2 * HOUR,
            ),
            _metric(
                onwatch.AGENT_HEALTHY,
                {"provider": "anthropic", "account_id": "default"},
                1,
            ),
            _metric(
                onwatch.AGENT_LAST_CYCLE_AGE,
                {"provider": "anthropic", "account_id": "default"},
                99,
            ),
            "go_goroutines 12",
        ]
    )


def _line(*parts: str) -> str:
    return "\n".join(parts)


def test_healthy_fixture_has_bounded_normalized_quota_and_no_raw_account_id():
    result = onwatch.summarize(onwatch.parse_metrics(_fixture()), now=NOW)

    assert result["status"] == "fresh"
    assert result["source"] == "onwatch_metrics"
    assert result["truncated"] is False
    assert [row["provider"] for row in result["providers"]] == ["anthropic", "codex"]
    codex = result["providers"][1]
    assert codex["account"] == "Work"
    assert codex["health"] == "fresh"
    assert codex["last_cycle_age_seconds"] == 98
    window = codex["windows"][0]
    assert window["window"] == "5h"
    assert window["utilization_percent"] == 42.5
    assert window["remaining_percent"] == 57.5
    assert window["reset_status"] == "scheduled"
    assert window["reset_in_seconds"] == HOUR
    assert window["status"] == "fresh"
    assert window["reasons"] == []
    assert '"1"' not in str(result)
    assert "Authorization" not in str(result)


def test_past_reset_is_stale_even_when_polling_is_healthy():
    reset = NOW - 30 * 24 * HOUR
    samples = onwatch.parse_metrics(
        _line(
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "codex", "quota_type": "5h", "account_id": "default"},
                10,
            ),
            _metric(
                onwatch.QUOTA_RESET,
                {"provider": "codex", "quota_type": "5h", "account_id": "default"},
                reset,
            ),
            _metric(
                onwatch.AGENT_HEALTHY,
                {"provider": "codex", "account_id": "default"},
                1,
            ),
            _metric(
                onwatch.AGENT_LAST_CYCLE_AGE,
                {"provider": "codex", "account_id": "default"},
                97,
            ),
        )
    )

    result = onwatch.summarize(samples, now=NOW)
    window = result["providers"][0]["windows"][0]
    assert result["status"] == "stale"
    assert result["providers"][0]["health"] == "fresh"
    assert window["reset_status"] == "passed"
    assert window["status"] == "stale"
    assert window["reasons"] == ["reset_timestamp_passed"]
    assert window["reset_in_seconds"] < 0

    health = onwatch._health_view(result)
    assert health["providers"][0]["stale_windows"] == 1


def test_reset_within_grace_is_due_not_stale():
    samples = onwatch.parse_metrics(
        _line(
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "anthropic", "quota_type": "5h", "account_id": "default"},
                10,
            ),
            _metric(
                onwatch.QUOTA_RESET,
                {"provider": "anthropic", "quota_type": "5h", "account_id": "default"},
                NOW - 60,
            ),
            _metric(onwatch.AGENT_HEALTHY, {"provider": "anthropic", "account_id": "default"}, 1),
        )
    )

    window = onwatch.summarize(samples, now=NOW)["providers"][0]["windows"][0]
    assert window["reset_status"] == "due"
    assert window["status"] == "fresh"


def test_missing_reset_is_explicit_and_not_unlimited():
    samples = onwatch.parse_metrics(
        _line(
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "copilot", "quota_type": "premium", "account_id": "default"},
                20,
            ),
            _metric(onwatch.AGENT_HEALTHY, {"provider": "copilot", "account_id": "default"}, 1),
            _metric(
                onwatch.AGENT_LAST_CYCLE_AGE, {"provider": "copilot", "account_id": "default"}, 60
            ),
        )
    )

    window = onwatch.summarize(samples, now=NOW)["providers"][0]["windows"][0]
    assert window["reset_at"] is None
    assert window["reset_status"] == "not_scheduled"
    assert window["status"] == "fresh"
    assert "unlimited" not in str(window).lower()


def test_missing_health_missing_utilization_and_invalid_values_are_unknown():
    samples = onwatch.parse_metrics(
        _line(
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "gemini", "quota_type": "gemini-2.5-pro", "account_id": "default"},
                10,
            ),
            _metric(
                onwatch.QUOTA_RESET,
                {"provider": "missing-util", "quota_type": "5h", "account_id": "default"},
                NOW + HOUR,
            ),
            _metric(
                onwatch.AGENT_HEALTHY,
                {"provider": "missing-util", "account_id": "default"},
                1,
            ),
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "nan", "quota_type": "5h", "account_id": "default"},
                "NaN",
            ),
            _metric(onwatch.AGENT_HEALTHY, {"provider": "nan", "account_id": "default"}, 1),
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "range", "quota_type": "5h", "account_id": "default"},
                120,
            ),
            _metric(onwatch.AGENT_HEALTHY, {"provider": "range", "account_id": "default"}, 1),
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "negative", "quota_type": "5h", "account_id": "default"},
                -5,
            ),
            _metric(onwatch.AGENT_HEALTHY, {"provider": "negative", "account_id": "default"}, 1),
        )
    )

    result = onwatch.summarize(samples, now=NOW)
    windows = {row["provider"]: row["windows"][0] for row in result["providers"] if row["windows"]}
    assert result["status"] == "unknown"
    assert windows["gemini"]["reasons"] == ["health_unknown"]
    assert windows["missing-util"]["reasons"] == ["utilization_missing"]
    assert windows["nan"]["reasons"] == ["utilization_invalid"]
    assert windows["nan"]["utilization_percent"] is None
    assert windows["nan"]["remaining_percent"] is None
    assert windows["range"]["reasons"] == ["utilization_out_of_range"]
    assert windows["range"]["utilization_percent"] is None
    assert windows["range"]["remaining_percent"] is None
    assert windows["negative"]["reasons"] == ["utilization_out_of_range"]
    assert windows["negative"]["utilization_percent"] is None
    assert windows["negative"]["remaining_percent"] is None


def test_health_only_account_is_unknown_not_fresh():
    samples = onwatch.parse_metrics(
        _line(
            _metric(
                onwatch.AGENT_HEALTHY,
                {"provider": "codex", "account_id": "default"},
                1,
            ),
            _metric(
                onwatch.AGENT_LAST_CYCLE_AGE,
                {"provider": "codex", "account_id": "default"},
                98,
            ),
        )
    )

    result = onwatch.summarize(samples, now=NOW)
    row = result["providers"][0]
    assert result["status"] == "unknown"
    assert row["health"] == "fresh"
    assert row["status"] == "unknown"
    assert row["reasons"] == ["quota_missing"]
    assert row["windows"] == []


def test_alias_containing_raw_account_id_is_omitted():
    account_id = "987654321"
    samples = onwatch.parse_metrics(
        _line(
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "codex", "quota_type": "5h", "account_id": account_id},
                10,
            ),
            _metric(onwatch.AGENT_HEALTHY, {"provider": "codex", "account_id": account_id}, 1),
            _metric(
                onwatch.ACCOUNT_INFO,
                {
                    "provider": "codex",
                    "account_id": account_id,
                    "account_name": "Work 987 654 321",
                },
                1,
            ),
        )
    )

    result = onwatch.summarize(samples, now=NOW)
    assert result["providers"][0]["account"] == "account-1"
    assert account_id not in str(result)


def test_stale_agent_marks_each_window_stale():
    samples = onwatch.parse_metrics(
        _line(
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "codex", "quota_type": "5h", "account_id": "default"},
                10,
            ),
            _metric(
                onwatch.QUOTA_RESET,
                {"provider": "codex", "quota_type": "5h", "account_id": "default"},
                NOW + HOUR,
            ),
            _metric(onwatch.AGENT_HEALTHY, {"provider": "codex", "account_id": "default"}, 0),
            _metric(
                onwatch.AGENT_LAST_CYCLE_AGE, {"provider": "codex", "account_id": "default"}, 1000
            ),
        )
    )

    result = onwatch.summarize(samples, now=NOW)
    assert result["providers"][0]["status"] == "stale"
    assert result["providers"][0]["windows"][0]["reasons"] == ["poll_stale"]


def test_numeric_accounts_are_labelled_without_raw_ids():
    lines = []
    for account_id in ("987654321", "123456789"):
        lines.extend(
            [
                _metric(
                    onwatch.QUOTA_UTILIZATION,
                    {
                        "provider": "codex",
                        "quota_type": "5h",
                        "account_id": account_id,
                    },
                    10,
                ),
                _metric(
                    onwatch.AGENT_HEALTHY,
                    {"provider": "codex", "account_id": account_id},
                    1,
                ),
            ]
        )
    result = onwatch.summarize(onwatch.parse_metrics(_line(*lines)), now=NOW)
    assert [row["account"] for row in result["providers"]] == ["account-1", "account-2"]
    assert "987654321" not in str(result)
    assert "123456789" not in str(result)


def test_absent_provider_is_unknown_not_invented():
    sample_text = _fixture()
    assert "opencode_go" not in sample_text
    result = onwatch.summarize(onwatch.parse_metrics(sample_text), now=NOW, provider="opencode_go")
    assert result["providers"] == []
    assert result["status"] == "unknown"


def test_output_is_capped():
    lines = []
    for index in range(400):
        lines.append(
            _metric(
                onwatch.QUOTA_UTILIZATION,
                {"provider": "codex", "quota_type": f"window-{index}", "account_id": "default"},
                10,
            )
        )
    lines.append(_metric(onwatch.AGENT_HEALTHY, {"provider": "codex", "account_id": "default"}, 1))
    result = onwatch.summarize(onwatch.parse_metrics(_line(*lines)), now=NOW)
    assert result["truncated"] is True
    assert len(result["providers"][0]["windows"]) == onwatch.MAX_WINDOWS


def test_malformed_metric_fails_closed():
    with pytest.raises(ValueError):
        onwatch.parse_metrics('onwatch_quota_utilization_percent{provider="codex"} nope')
    with pytest.raises(ValueError):
        onwatch.parse_metrics('onwatch_quota_utilization_percent{provider="codex" 1')


@pytest.mark.parametrize(
    "url",
    [
        "https://onwatch.example.test",
        "http://127.0.0.1:9211",
        "http://localhost:9211/",
    ],
)
def test_supported_origins(monkeypatch, url):
    monkeypatch.setenv("KULE_ONWATCH_URL", url)
    assert onwatch._base_url() == url.rstrip("/")


@pytest.mark.parametrize(
    "url",
    [
        "http://onwatch.example.test:9211",
        "https://user:pass@onwatch.example.test",
        "https://onwatch.example.test/metrics",
        "https://onwatch.example.test?x=1",
        "https://onwatch.example.test/#fragment",
    ],
)
def test_rejected_origins(monkeypatch, url):
    monkeypatch.setenv("KULE_ONWATCH_URL", url)
    with pytest.raises(ValueError):
        onwatch._base_url()


def test_token_file_is_read_but_never_embedded_in_errors(monkeypatch, tmp_path):
    token = tmp_path / "token"
    token.write_text("synthetic-onwatch-secret")
    monkeypatch.setenv("KULE_ONWATCH_TOKEN_FILE", str(token))
    assert onwatch._auth_headers() == {"Authorization": "Bearer synthetic-onwatch-secret"}

    token.unlink()
    with pytest.raises(RuntimeError) as exc:
        onwatch._auth_headers()
    assert "synthetic-onwatch-secret" not in str(exc.value)

    token.write_text("  \n")
    with pytest.raises(RuntimeError, match="empty"):
        onwatch._auth_headers()


async def test_metrics_request_returns_bounded_body():
    seen = []

    def handler(request):
        seen.append((str(request.url), request.headers.get("Authorization")))
        return httpx2.Response(200, text=_fixture())

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler), follow_redirects=False
    ) as client:
        text = await onwatch._get_metrics(
            client, "http://127.0.0.1:9211", {"Authorization": "Bearer synthetic"}
        )
    assert "onwatch_quota_utilization_percent" in text
    assert seen == [("http://127.0.0.1:9211/metrics", "Bearer synthetic")]


async def test_metrics_request_uses_token_and_refuses_redirects():
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers.get("Authorization")))
        return httpx2.Response(302, headers={"Location": "https://attacker.invalid/metrics"})

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler), follow_redirects=False
    ) as client:
        with pytest.raises(RuntimeError, match="redirect refused"):
            await onwatch._get_metrics(
                client, "http://127.0.0.1:9211", {"Authorization": "Bearer synthetic"}
            )
    assert seen == [("127.0.0.1", "Bearer synthetic")]


async def test_http_error_does_not_echo_token_or_body(monkeypatch):
    def handler(request):
        return httpx2.Response(401, text="synthetic-onwatch-secret")

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler), follow_redirects=False
    ) as client:
        with pytest.raises(RuntimeError) as exc:
            await onwatch._get_metrics(
                client, "https://onwatch.example.test", {"Authorization": "Bearer secret"}
            )
    assert "synthetic-onwatch-secret" not in str(exc.value)
    assert "Bearer secret" not in str(exc.value)


async def test_oversized_response_is_refused(monkeypatch):
    monkeypatch.setattr(onwatch, "MAX_BODY_BYTES", 5)

    def handler(request):
        return httpx2.Response(200, text="0123456789")

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler), follow_redirects=False
    ) as client:
        with pytest.raises(RuntimeError, match="too large"):
            await onwatch._get_metrics(client, "https://onwatch.example.test", {})


def _gateway(tmp_path):
    caller = {"claims": {"sub": "operator", "groups": ["ops"]}}
    audit = tmp_path / "audit.jsonl"
    gateway = FastMCP(
        "kule-onwatch",
        middleware=[
            OperatorMiddleware(
                policy=Policy(required_group="ops", exec_group="exec", exec_enabled=False),
                audit=AuditLog(audit),
                kill_switch=tmp_path / "DISABLED",
                timeout_seconds=5,
                max_output_bytes=64 * 1024,
                claims_getter=lambda: caller["claims"],
            )
        ],
    )
    return gateway, caller, audit


async def test_register_is_off_without_configuration(monkeypatch):
    monkeypatch.delenv("KULE_ONWATCH_URL", raising=False)
    mcp = FastMCP("kule-onwatch")
    onwatch.register(mcp, timeout_seconds=5)
    async with Client(mcp) as client:
        assert await client.list_tools() == []


async def test_registered_tools_are_operator_only_read_only_and_bounded(monkeypatch, tmp_path):
    monkeypatch.setenv("KULE_ONWATCH_URL", "http://127.0.0.1:9211")
    snapshot = onwatch.summarize(onwatch.parse_metrics(_fixture()), now=NOW)

    async def fake_snapshot(*, timeout_seconds: float) -> dict:
        return snapshot

    monkeypatch.setattr(onwatch, "fetch_snapshot", fake_snapshot)
    gateway, caller, audit = _gateway(tmp_path)
    onwatch.register(gateway, timeout_seconds=5)

    async with Client(gateway) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
        assert set(tools) == {
            "onwatch_quota_status",
            "onwatch_quota_health",
            "onwatch_providers",
        }
        assert all(tool.annotations.read_only_hint for tool in tools.values())
        status = await client.call_tool("onwatch_quota_status", {})
        assert status.data["status"] == "fresh"
        filtered = await client.call_tool("onwatch_quota_status", {"provider": "codex"})
        assert [row["provider"] for row in filtered.data["providers"]] == ["codex"]
        health = await client.call_tool("onwatch_quota_health", {})
        assert health.data["providers"][0]["window_count"] == 1
        providers = await client.call_tool("onwatch_providers", {})
        assert providers.data["providers"][1]["windows"] == ["5h"]
        with pytest.raises(ToolError):
            await client.call_tool("onwatch_quota_status", {"provider": "Codex;drop"})

    caller["claims"] = {"sub": "guest", "groups": []}
    async with Client(gateway) as client:
        assert await client.list_tools() == []
        with pytest.raises(ToolError, match="not authorized"):
            await client.call_tool("onwatch_quota_status", {})
    assert verify(audit)[0]


def test_utc_timestamp_is_explicit():
    result = onwatch.summarize(onwatch.parse_metrics(_fixture()), now=NOW)
    parsed = datetime.fromisoformat(result["observed_at"])
    assert parsed.tzinfo == UTC
