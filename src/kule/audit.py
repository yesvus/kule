"""Append-only JSONL audit log with a hash chain.

Each record stores the SHA-256 of the previous line, so editing or deleting a
line that has a successor breaks verification from that point on. Limits:

- The newest line has no successor, so truncating or editing the tail is not
  detectable from the file alone. Ship records off-host (or anchor the latest
  hash elsewhere) if that matters.
- A host administrator can rewrite the whole file and recompute the chain.

Writers take an exclusive ``flock`` and re-read the tail on every write, so
several processes or instances appending to one file keep a single chain.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .redact import redact

GENESIS = "0" * 64
_TAIL_CHUNK = 4096


def _line_hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def _last_line(fd: int) -> bytes | None:
    """Return the last complete line (without newline), or None if empty."""
    end = os.lseek(fd, 0, os.SEEK_END)
    if end == 0:
        return None
    buf = b""
    pos = end
    while pos > 0:
        step = min(_TAIL_CHUNK, pos)
        pos -= step
        buf = os.pread(fd, step, pos) + buf
        stripped = buf.rstrip(b"\n")
        idx = stripped.rfind(b"\n")
        if idx != -1:
            return stripped[idx + 1 :]
    return buf.rstrip(b"\n") or None


def _repair_torn_tail(fd: int) -> int:
    """Truncate a partial final line left by a crash. Returns bytes removed."""
    end = os.lseek(fd, 0, os.SEEK_END)
    if end == 0 or os.pread(fd, 1, end - 1) == b"\n":
        return 0
    pos = end
    while pos > 0:
        step = min(_TAIL_CHUNK, pos)
        pos -= step
        idx = os.pread(fd, step, pos).rfind(b"\n")
        if idx != -1:
            keep = pos + idx + 1
            os.ftruncate(fd, keep)
            return end - keep
    os.ftruncate(fd, 0)
    return end


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        removed = self._with_file(_repair_torn_tail)
        if removed:
            self.write("audit_repair", removed_bytes=removed, reason="torn final line")

    def _with_file(self, fn):
        fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                return fn(fd)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def write(self, event: str, **fields: Any) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "event": event,
            **redact(fields),
        }

        def append(fd: int) -> None:
            last = _last_line(fd)
            record["prev"] = GENESIS if last is None else _line_hash(last)
            line = json.dumps(record, sort_keys=True, default=str).encode()
            os.write(fd, line + b"\n")
            os.fsync(fd)

        with self._lock:
            self._with_file(append)


def verify(path: Path) -> tuple[bool, int]:
    """Return (ok, number_of_valid_lines). Raises OSError if unreadable."""
    prev = GENESIS
    count = 0
    with path.open("rb") as fh:
        for raw in fh:
            line = raw.rstrip(b"\n")
            if not line:
                return False, count
            try:
                record = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return False, count
            if not isinstance(record, dict) or record.get("prev") != prev:
                return False, count
            prev = _line_hash(line)
            count += 1
    return True, count
