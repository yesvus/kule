"""Append-only JSONL audit log with a hash chain.

Each record stores the SHA-256 of the previous line, so deleting or editing a
line breaks verification from that point on. This detects tampering after the
fact; it does not prevent a host administrator from rewriting the whole file.
Ship the log off-host for stronger guarantees.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .redact import redact

GENESIS = "0" * 64


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        with self.path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            buf = b""
            while pos > 0:
                step = min(4096, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                lines = buf.rstrip(b"\n").split(b"\n")
                if len(lines) > 1 or pos == 0:
                    return _line_hash(lines[-1].decode())
        return GENESIS

    def write(self, event: str, **fields: Any) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "event": event,
            **redact(fields),
        }
        with self._lock:
            record["prev"] = self._prev
            line = json.dumps(record, sort_keys=True, default=str)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            try:
                os.write(fd, (line + "\n").encode())
            finally:
                os.close(fd)
            self._prev = _line_hash(line)


def verify(path: Path) -> tuple[bool, int]:
    """Return (ok, number_of_valid_lines)."""
    prev = GENESIS
    count = 0
    with path.open() as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return False, count
            if record.get("prev") != prev:
                return False, count
            prev = _line_hash(line)
            count += 1
    return True, count
