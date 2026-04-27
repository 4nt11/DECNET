"""MVP SSH-flavoured driver.

Two action shapes:

* :class:`~decnet.orchestrator.scheduler.TrafficAction` — exec a tiny
  Python one-liner *inside the source decky's ssh container* that opens
  TCP/22 against the destination decky's IP and reads the SSH banner.
  This generates real on-the-wire SSH-protocol traffic between the two
  containers (sshd announces the banner on connect), without us having
  to ship credentials anywhere.
* :class:`~decnet.orchestrator.scheduler.FileAction` — drop / refresh a
  file inside the destination decky's ssh container via ``docker exec``.

Both shell out via :func:`asyncio.create_subprocess_exec` with argv
lists — never a shell string — so an attacker-controllable decky name
or IP can't escape into a shell.
"""
from __future__ import annotations

import asyncio
import shlex
from typing import Any

import base64
from datetime import datetime, timezone

from decnet.logging import get_logger
from decnet.orchestrator.drivers.base import ActivityDriver, ActivityResult
from decnet.orchestrator.scheduler import (
    Action,
    EditAction,
    FileAction,
    TrafficAction,
)

log = get_logger("orchestrator.ssh")

_DOCKER = "docker"
# Per-call wall-clock cap.  The orchestrator runs serially (one action
# per tick); a wedged docker exec must not stall the whole worker.
_TIMEOUT = 8.0

# Container suffix convention: services/*.py emit container_name as
# ``<decky_name>-<service>``.  The MVP only drives the ssh service.
_SSH_CONTAINER_SUFFIX = "-ssh"


def _container_for(decky_name: str) -> str:
    return f"{decky_name}{_SSH_CONTAINER_SUFFIX}"


async def _run(argv: list[str]) -> tuple[int, str, str]:
    """Spawn *argv* and capture (rc, stdout, stderr).

    Returns ``(rc=124, "", "timeout")`` on wall-clock expiry.  Never
    raises — orchestrator success/failure is a payload attribute, not
    an exception.
    """
    return await _run_with_stdin(argv, None)


async def _run_with_stdin(
    argv: list[str], stdin_bytes: bytes | None,
) -> tuple[int, str, str]:
    """Spawn *argv*, optionally feeding *stdin_bytes*, and capture rc+output.

    Used by :meth:`SSHDriver.plant_file` to stream base64 payloads via
    stdin (avoids ARG_MAX on large blobs — same fix as the canary
    planter in commit c17b9e0).  Same failure semantics as :func:`_run`.
    """
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
            proc.communicate(stdin_bytes), timeout=_TIMEOUT,
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


# Python one-liner that probes the destination's SSH banner.  Kept inline
# so the driver has zero filesystem dependencies on the host side; the
# *container* needs python3 (ssh service template ships it).
_PROBE_PY = (
    "import socket,sys;"
    "s=socket.socket();s.settimeout(3);"
    "s.connect((sys.argv[1], 22));"
    "b=s.recv(128);s.close();"
    "sys.stdout.write(b.decode('latin1','replace'))"
)


class SSHDriver(ActivityDriver):
    """Concrete :class:`ActivityDriver` for SSH-flavoured actions."""

    async def run(self, action: Action) -> ActivityResult:
        if isinstance(action, TrafficAction):
            return await self._run_traffic(action)
        if isinstance(action, FileAction):
            return await self._run_file(action)
        if isinstance(action, EditAction):
            return await self._run_edit(action)
        raise TypeError(f"unsupported action type: {type(action)!r}")

    async def _run_traffic(self, action: TrafficAction) -> ActivityResult:
        container = _container_for(action.src_name)
        argv = [
            _DOCKER, "exec", container,
            "python3", "-c", _PROBE_PY, action.dst_ip,
        ]
        rc, stdout, stderr = await _run(argv)
        success = rc == 0 and stdout.startswith("SSH-")
        payload: dict[str, Any] = {
            "src_decky": action.src_name,
            "dst_decky": action.dst_name,
            "dst_ip": action.dst_ip,
            "dst_port": 22,
            "rc": rc,
            "banner": stdout.strip()[:128] if success else None,
            "stderr": stderr.strip()[:256] if not success else None,
        }
        if not success:
            log.debug(
                "orchestrator.ssh.traffic failed src=%s dst=%s rc=%d stderr=%r",
                action.src_name, action.dst_name, rc, stderr[:120],
            )
        return ActivityResult(success=success, payload=payload)

    async def _run_edit(self, action: EditAction) -> ActivityResult:
        """Mutate an existing synthetic file in place.

        The realism planner already loaded the previous body from the
        ``synthetic_files`` row, so we don't re-fetch via ``read_file``;
        the body the planner saw is the body we mutate.  This avoids a
        TOCTOU window where the file changed between pick and apply
        (the realism worker is the only writer in the MVP, but the
        contract should still be tight).
        """
        from decnet.realism.bodies import next_iteration as _next_iteration
        from decnet.realism.taxonomy import ContentClass

        try:
            cls = ContentClass(action.content_class)
        except ValueError:
            return ActivityResult(
                success=False,
                payload={
                    "dst_decky": action.dst_name,
                    "path": action.path,
                    "error": f"unknown content_class: {action.content_class!r}",
                },
            )
        try:
            new_body = _next_iteration(
                cls, action.persona, action.previous_body,
            )
        except KeyError:
            return ActivityResult(
                success=False,
                payload={
                    "dst_decky": action.dst_name,
                    "path": action.path,
                    "error": (
                        f"content_class={cls!s} does not support edits"
                    ),
                },
            )
        result = await self.plant_file(
            action.dst_name,
            action.path,
            new_body.encode("utf-8"),
            mode=0o644,
            mtime=action.mtime,
        )
        # Carry edit-specific metadata through to the orchestrator
        # event payload so the worker's synthetic_files bump (and the
        # dashboard's lineage view) sees what actually landed.
        if result.success:
            result.payload["new_body"] = new_body
            result.payload["new_body_bytes"] = len(new_body.encode("utf-8"))
            result.payload["synthetic_file_uuid"] = action.synthetic_file_uuid
        return result

    async def _run_file(self, action: FileAction) -> ActivityResult:
        # FileAction's content is a string; the realism path uses
        # bytes-typed plant_file so binary blobs (DOCX/PDF, future
        # canary artifacts) survive the wire.  Encode-once here.
        # mtime carries through from the realism planner so the file
        # doesn't stamp at wall-clock-now (the realism failure today).
        return await self.plant_file(
            action.dst_name,
            action.path,
            action.content.encode("utf-8"),
            mode=0o644,
            mtime=action.mtime,
        )

    async def plant_file(
        self,
        decky_name: str,
        path: str,
        content: bytes,
        *,
        mode: int = 0o600,
        mtime: datetime | None = None,
    ) -> ActivityResult:
        """Write *content* to *path* inside *decky_name*'s ssh container.

        Streams base64 via stdin (mirrors :mod:`decnet.canary.planter`'s
        ARG_MAX-safe write — see commit c17b9e0).  Sets file mode and,
        when *mtime* is provided, ``touch -d`` to backdate the file so
        it doesn't all stamp at wall-clock-now (the realism failure
        this migration is fixing).
        """
        container = _container_for(decky_name)
        b64 = base64.b64encode(content).decode("ascii")
        # touch -d accepts ISO 8601; we always emit UTC so the
        # container's local TZ doesn't drift the mtime.
        if mtime is not None:
            ts = mtime.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            touch_cmd = f"touch -d {shlex.quote(ts)} {shlex.quote(path)}"
        else:
            touch_cmd = f"touch {shlex.quote(path)}"
        sh_cmd = (
            f"mkdir -p {shlex.quote(_dirname(path))} && "
            f"base64 -d > {shlex.quote(path)} && "
            f"chmod {mode:o} {shlex.quote(path)} && "
            f"{touch_cmd}"
        )
        argv = [_DOCKER, "exec", "-i", container, "sh", "-c", sh_cmd]
        rc, _stdout, stderr = await _run_with_stdin(argv, b64.encode("ascii"))
        success = rc == 0
        payload: dict[str, Any] = {
            "dst_decky": decky_name,
            "path": path,
            "bytes": len(content),
            "rc": rc,
            "stderr": stderr.strip()[:256] if not success else None,
        }
        return ActivityResult(success=success, payload=payload)

    async def read_file(self, decky_name: str, path: str) -> bytes:
        """Read *path* from inside *decky_name*'s ssh container.

        Used by the realism edit-in-place flow: the driver fetches
        the previous body, the realism engine produces the next
        iteration, the driver re-plants it via :meth:`plant_file`.

        Raises :class:`FileNotFoundError` when the container path
        doesn't exist (rc=1 from ``cat`` with stderr ``No such
        file``).  Other failures raise :class:`RuntimeError` carrying
        the docker stderr.
        """
        container = _container_for(decky_name)
        argv = [_DOCKER, "exec", container, "cat", path]
        rc, stdout, stderr = await _run(argv)
        if rc == 0:
            return stdout.encode("utf-8") if isinstance(stdout, str) else stdout
        if "No such file" in stderr or "no such file" in stderr.lower():
            raise FileNotFoundError(f"{path} not present in {decky_name}")
        raise RuntimeError(
            f"docker exec cat failed rc={rc} stderr={stderr.strip()[:256]!r}"
        )


def _dirname(path: str) -> str:
    """Pure-string dirname.  We can't trust ``os.path.dirname`` on the
    host to share the destination container's separator semantics, but
    deckies are POSIX so a plain ``rfind('/')`` suffices."""
    idx = path.rfind("/")
    if idx <= 0:
        return "/"
    return path[:idx]
