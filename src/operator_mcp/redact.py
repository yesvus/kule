"""Best-effort secret redaction for audit records and tool output.

This is a safety net, not a guarantee: tools must still avoid reading secrets.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "[REDACTED]"
# Strings longer than this are truncated before scanning. Bounds regex cost
# per call and keeps oversized arguments out of the audit log.
MAX_SCAN_CHARS = 4096

_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    # Any Authorization header value, whatever the scheme (Basic, Token, ...).
    re.compile(r"(?i)(\bauthorization)(\s*[=:]\s*)([^\r\n,;}\]]+)"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    # key=value / key: value / "key": "value", including prefixed identifiers
    # such as DB_PASSWORD, OPENAI_API_KEY or access_token.
    re.compile(
        r"(?i)([A-Za-z0-9_.-]{0,40}(?:password|passwd|secret|token|api[_-]?key)"
        r"[A-Za-z0-9_.-]{0,20}[\"']?)"
        r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)"
    ),
]

_SENSITIVE_KEYS = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)")


def redact_text(text: str) -> str:
    if len(text) > MAX_SCAN_CHARS:
        text = f"{text[:MAX_SCAN_CHARS]}...[truncated {len(text) - MAX_SCAN_CHARS} chars]"
    for pattern in _PATTERNS:
        if pattern.groups >= 3:
            text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)
        else:
            text = pattern.sub(MASK, text)
    return text


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str):
                sensitive = bool(_SENSITIVE_KEYS.search(k))
                k = redact_text(k)
                out[k] = MASK if sensitive else redact(v)
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value
