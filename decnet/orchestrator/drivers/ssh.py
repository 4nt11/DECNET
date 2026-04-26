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

from decnet.logging import get_logger
from decnet.orchestrator.drivers.base import ActivityResult
from decnet.orchestrator.scheduler import Action, FileAction, TrafficAction

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
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return 127, "", f"argv[0] not found: {exc}"
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=_TIMEOUT)
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


class SSHDriver:
    """Concrete :class:`Driver` for the MVP."""

    async def run(self, action: Action) -> ActivityResult:
        if isinstance(action, TrafficAction):
            return await self._run_traffic(action)
        if isinstance(action, FileAction):
            return await self._run_file(action)
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

    async def _run_file(self, action: FileAction) -> ActivityResult:
        container = _container_for(action.dst_name)
        # `tee` is in coreutils on every base image; using it (instead of
        # `>` redirection) keeps the argv free of shell metacharacters
        # the dst_name/path could otherwise weaponise.  Path validation
        # still belongs upstream — the scheduler's templates are fixed.
        # We do invoke `sh -c` so the parent dir gets mkdir'd in one
        # call; the sh argv stays trivially auditable.
        sh_cmd = (
            f"mkdir -p {shlex.quote(_dirname(action.path))} && "
            f"printf %s {shlex.quote(action.content)} > {shlex.quote(action.path)} && "
            f"touch {shlex.quote(action.path)}"
        )
        argv = [_DOCKER, "exec", container, "sh", "-c", sh_cmd]
        rc, stdout, stderr = await _run(argv)
        success = rc == 0
        payload: dict[str, Any] = {
            "dst_decky": action.dst_name,
            "path": action.path,
            "bytes": len(action.content.encode("utf-8")),
            "rc": rc,
            "stderr": stderr.strip()[:256] if not success else None,
        }
        return ActivityResult(success=success, payload=payload)


def _dirname(path: str) -> str:
    """Pure-string dirname.  We can't trust ``os.path.dirname`` on the
    host to share the destination container's separator semantics, but
    deckies are POSIX so a plain ``rfind('/')`` suffices."""
    idx = path.rfind("/")
    if idx <= 0:
        return "/"
    return path[:idx]
