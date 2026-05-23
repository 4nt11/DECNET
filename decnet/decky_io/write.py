# SPDX-License-Identifier: AGPL-3.0-or-later
"""``docker exec``-driven file write/delete inside a decky container.

The write path streams a base64-encoded payload over stdin to
``base64 -d`` inside the container, so binary content of any size up
to docker's stream limits is safe — interpolating bytes into argv
would trip ARG_MAX (~128 KB on most kernels) for any non-trivial blob.
"""
from __future__ import annotations

import asyncio
import base64
import shlex
from datetime import datetime, timezone
from typing import Optional

from decnet.logging import get_logger

log = get_logger("decky_io.write")

_DOCKER = "docker"
_DEFAULT_TIMEOUT = 8.0


def _dirname(path: str) -> str:
    idx = path.rfind("/")
    if idx <= 0:
        return "/"
    return path[:idx]


async def _run(
    argv: list[str],
    *,
    stdin_bytes: Optional[bytes] = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return 127, "", f"argv[0] not found: {exc}"
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes), timeout=timeout,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return 124, "", "timeout"
    return (
        proc.returncode if proc.returncode is not None else -1,
        stdout.decode("utf-8", "replace"),
        stderr.decode("utf-8", "replace"),
    )


async def write_file_to_container(
    container: str,
    path: str,
    content: bytes,
    *,
    mode: int = 0o644,
    mtime: Optional[datetime] = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> tuple[bool, Optional[str]]:
    """Write *content* to *path* inside *container* via ``docker exec``.

    The directory above *path* is created if missing; *mode* is applied
    after the write; when *mtime* is provided the file is backdated via
    ``touch -d`` (UTC ISO 8601).

    Returns ``(success, error_or_none)``.  ``error`` is the trimmed
    docker stderr on rc != 0, or a short "rc=<n>" if stderr was empty.
    """
    if not path:
        return False, "empty path"

    encoded = base64.b64encode(content)
    parts = [
        f"mkdir -p {shlex.quote(_dirname(path))}",
        f"base64 -d > {shlex.quote(path)}",
        f"chmod {mode:o} {shlex.quote(path)}",
    ]
    if mtime is not None:
        ts = mtime.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        parts.append(f"touch -d {shlex.quote(ts)} {shlex.quote(path)}")
    sh_cmd = " && ".join(parts)
    argv = [_DOCKER, "exec", "-i", container, "sh", "-c", sh_cmd]
    rc, _stdout, stderr = await _run(argv, stdin_bytes=encoded, timeout=timeout)
    success = rc == 0
    if success:
        return True, None
    err = stderr.strip()[:256] or f"rc={rc}"
    log.warning(
        "decky_io.write failed container=%s path=%s rc=%d stderr=%r",
        container, path, rc, stderr[:120],
    )
    return False, err


async def delete_file_from_container(
    container: str,
    path: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
) -> tuple[bool, Optional[str]]:
    """Best-effort ``rm -f`` of *path* inside *container*.

    Returns ``(success, error_or_none)``.  ``rm -f`` returns rc=0 even
    when the file is already gone, so a True result here means "the
    file is not present after this call", regardless of who unlinked it.
    """
    sh_cmd = f"rm -f {shlex.quote(path)}"
    argv = [_DOCKER, "exec", container, "sh", "-c", sh_cmd]
    rc, _stdout, stderr = await _run(argv, timeout=timeout)
    if rc == 0:
        return True, None
    return False, stderr.strip()[:256] or f"rc={rc}"
