"""Tiny in-container Tezgah runner, sent via python -c; no daemon or host shell.

Executed only by the pinned Pod's dev container through Kubernetes pods/exec.
The calling Kubernetes identity MUST additionally be restricted by resourceNames.
"""

from __future__ import annotations

import base64
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path("/workspace")
MAX_BYTES = 8192
MAX_SECONDS = 8.0
MARKER = "KULE_WS_RESULT:"
_DENIED_PARTS = frozenset(
    {
        ".git",
        ".ssh",
        ".config",
        ".env",
        "secrets",
        "credentials",
        "private",
        "tokens",
        ".kube",
        ".aws",
        ".oci",
    }
)


def _path_parts(value: str) -> tuple[str, ...]:
    if not value or len(value) > 240 or value.startswith("/") or "\x00" in value:
        raise ValueError("path must be a short relative workspace path")
    parts = tuple(value.split("/"))
    if any(
        not p or p in (".", "..") or p.startswith(".") or p.lower() in _DENIED_PARTS for p in parts
    ):
        raise ValueError("hidden, sensitive, or traversal path refused")
    return parts


def _parent(value: str) -> tuple[int, str]:
    parts = _path_parts(value)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(ROOT, flags)
    try:
        for part in parts[:-1]:
            next_dir = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = next_dir
        return directory, parts[-1]
    except BaseException:
        os.close(directory)
        raise


def _read(path: str) -> dict:
    directory, leaf = _parent(path)
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("not a regular file")
            data = os.read(fd, MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError("file exceeds read limit")
            return {"path": path, "text": data.decode("utf-8"), "bytes": len(data)}
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def _write(path: str, text: str) -> dict:
    data = text.encode("utf-8")
    if len(data) > MAX_BYTES:
        raise ValueError("content exceeds write limit")
    directory, leaf = _parent(path)
    tmp = ".kule-" + uuid.uuid4().hex
    try:
        try:
            mode = os.stat(leaf, dir_fd=directory, follow_symlinks=False).st_mode
        except FileNotFoundError:
            mode = None
        if mode is not None and not stat.S_ISREG(mode):
            raise ValueError("destination must be a regular file")
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        try:
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, leaf, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            try:
                os.unlink(tmp, dir_fd=directory)
            except FileNotFoundError:
                pass
        return {"path": path, "bytes": len(data), "written": True}
    finally:
        os.close(directory)


def _kill(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    proc.wait(timeout=2)


def _exec(command: str) -> dict:
    if not command.strip() or len(command.encode()) > 4096 or "\x00" in command:
        raise ValueError("command must be 1..4096 bytes")
    proc = subprocess.Popen(  # noqa: S603 (intentional in-container dev-user exec)
        ["/bin/sh", "-c", command],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
    )
    output = bytearray()
    timed_out = False
    exceeded = False
    deadline = time.monotonic() + MAX_SECONDS
    assert proc.stdout is not None
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            ready = selector.select(timeout=min(remaining, 0.2))
            if not ready:
                continue
            chunk = os.read(proc.stdout.fileno(), min(MAX_BYTES + 1 - len(output), 65536))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_BYTES:
                exceeded = True
                break
    if timed_out or exceeded:
        _kill(proc)
    else:
        proc.wait(timeout=2)
    return {
        "exit_code": proc.returncode,
        "stdout": output[:MAX_BYTES].decode("utf-8", "replace"),
        "timed_out": timed_out,
        "output_exceeded": exceeded,
    }


def run(operation: str, payload: dict) -> dict:
    if operation == "exec":
        return _exec(payload["command"])
    if operation == "read":
        return _read(payload["path"])
    if operation == "write":
        return _write(payload["path"], payload["text"])
    raise ValueError("unsupported workspace operation")


def main() -> None:
    try:
        operation = sys.argv[1]
        payload = json.loads(base64.b64decode(sys.argv[2], validate=True))
        result = run(operation, payload)
    except Exception as exc:
        result = {"error": type(exc).__name__, "message": str(exc)[:200]}
    print(MARKER + json.dumps(result, ensure_ascii=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
