"""Update/rollback orchestrator for the DECNET self-updater.

Directory layout owned by this module (root = ``install_dir``):

    <install_dir>/
        current -> releases/active      (symlink; atomic swap == promotion)
        releases/
            active/                     (working tree; has its own .venv)
            prev/                       (last good snapshot; restored on failure)
            active.new/                 (staging; only exists mid-update)
        agent.pid                       (PID of the agent process we spawned)

Rollback semantics: if the agent doesn't come back healthy after an update,
we swap the symlink back to ``prev``, restart the agent, and return the
captured pip/agent stderr to the caller.

Seams for tests — every subprocess call goes through a module-level hook
(`_run_pip`, `_spawn_agent`, `_probe_agent`) so tests can monkeypatch them
without actually touching the filesystem's Python toolchain.
"""
from __future__ import annotations

import dataclasses
import os
import pathlib
import shutil
import signal
import ssl
import subprocess  # nosec B404
import sys
import tarfile
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import httpx

from decnet.logging import get_logger
from decnet.swarm import pki

log = get_logger("updater.executor")

DEFAULT_INSTALL_DIR = pathlib.Path("/opt/decnet")
AGENT_PROBE_URL = "https://127.0.0.1:8765/health"
AGENT_PROBE_ATTEMPTS = 10
AGENT_PROBE_BACKOFF_S = 1.0
AGENT_RESTART_GRACE_S = 10.0


# ------------------------------------------------------------------- errors

class UpdateError(RuntimeError):
    """Raised when an update fails but the install dir is consistent.

    Carries the captured stderr so the master gets actionable output.
    """

    def __init__(self, message: str, *, stderr: str = "", rolled_back: bool = False):
        super().__init__(message)
        self.stderr = stderr
        self.rolled_back = rolled_back


# -------------------------------------------------------------------- types

@dataclasses.dataclass(frozen=True)
class Release:
    slot: str
    sha: Optional[str]
    installed_at: Optional[datetime]

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot": self.slot,
            "sha": self.sha,
            "installed_at": self.installed_at.isoformat() if self.installed_at else None,
        }


# ---------------------------------------------------------------- internals

def _releases_dir(install_dir: pathlib.Path) -> pathlib.Path:
    return install_dir / "releases"


def _active_dir(install_dir: pathlib.Path) -> pathlib.Path:
    return _releases_dir(install_dir) / "active"


def _prev_dir(install_dir: pathlib.Path) -> pathlib.Path:
    return _releases_dir(install_dir) / "prev"


def _staging_dir(install_dir: pathlib.Path) -> pathlib.Path:
    return _releases_dir(install_dir) / "active.new"


def _current_symlink(install_dir: pathlib.Path) -> pathlib.Path:
    return install_dir / "current"


def _pid_file(install_dir: pathlib.Path) -> pathlib.Path:
    return install_dir / "agent.pid"


def _manifest_file(release: pathlib.Path) -> pathlib.Path:
    return release / ".decnet-release.json"


def _venv_python(release: pathlib.Path) -> pathlib.Path:
    return release / ".venv" / "bin" / "python"


# ------------------------------------------------------------------- public

def read_release(release: pathlib.Path) -> Release:
    """Read the release manifest sidecar; tolerate absence."""
    slot = release.name
    mf = _manifest_file(release)
    if not mf.is_file():
        return Release(slot=slot, sha=None, installed_at=None)
    import json

    try:
        data = json.loads(mf.read_text())
    except (json.JSONDecodeError, OSError):
        return Release(slot=slot, sha=None, installed_at=None)
    ts = data.get("installed_at")
    return Release(
        slot=slot,
        sha=data.get("sha"),
        installed_at=datetime.fromisoformat(ts) if ts else None,
    )


def list_releases(install_dir: pathlib.Path) -> list[Release]:
    out: list[Release] = []
    for slot_dir in (_active_dir(install_dir), _prev_dir(install_dir)):
        if slot_dir.is_dir():
            out.append(read_release(slot_dir))
    return out


def clean_stale_staging(install_dir: pathlib.Path) -> None:
    """Remove a half-extracted ``active.new`` left by a crashed update."""
    staging = _staging_dir(install_dir)
    if staging.exists():
        log.warning("removing stale staging dir %s", staging)
        shutil.rmtree(staging, ignore_errors=True)


def extract_tarball(tarball_bytes: bytes, dest: pathlib.Path) -> None:
    """Extract a gzipped tarball into ``dest`` (must not pre-exist).

    Rejects absolute paths and ``..`` traversal in the archive.
    """
    import io

    dest.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            name = member.name
            if name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts:
                raise UpdateError(f"unsafe path in tarball: {name!r}")
        tar.extractall(dest)  # nosec B202 — validated above


# ---------------------------------------------------------------- seams

def _run_pip(release: pathlib.Path) -> subprocess.CompletedProcess:
    """Create a venv in ``release/.venv`` and pip install -e . into it.

    Monkeypatched in tests so the test suite never shells out.
    """
    venv_dir = release / ".venv"
    if not venv_dir.exists():
        subprocess.run(  # nosec B603
            [sys.executable, "-m", "venv", str(venv_dir)],
            check=True, capture_output=True, text=True,
        )
    py = _venv_python(release)
    return subprocess.run(  # nosec B603
        [str(py), "-m", "pip", "install", "-e", str(release)],
        check=False, capture_output=True, text=True,
    )


def _spawn_agent(install_dir: pathlib.Path) -> int:
    """Launch ``decnet agent --daemon`` using the current-symlinked venv.

    Returns the new PID. Monkeypatched in tests.
    """
    py = _venv_python(_current_symlink(install_dir).resolve())
    proc = subprocess.Popen(  # nosec B603
        [str(py), "-m", "decnet", "agent", "--daemon"],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _pid_file(install_dir).write_text(str(proc.pid))
    return proc.pid


def _stop_agent(install_dir: pathlib.Path, grace: float = AGENT_RESTART_GRACE_S) -> None:
    """SIGTERM the PID we spawned; SIGKILL if it doesn't exit in ``grace`` s."""
    pid_file = _pid_file(install_dir)
    if not pid_file.is_file():
        return
    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _probe_agent(
    agent_dir: pathlib.Path = pki.DEFAULT_AGENT_DIR,
    url: str = AGENT_PROBE_URL,
    attempts: int = AGENT_PROBE_ATTEMPTS,
    backoff_s: float = AGENT_PROBE_BACKOFF_S,
) -> tuple[bool, str]:
    """Local mTLS health probe against the agent. Returns (ok, detail)."""
    worker_key = agent_dir / "worker.key"
    worker_crt = agent_dir / "worker.crt"
    ca = agent_dir / "ca.crt"
    if not (worker_key.is_file() and worker_crt.is_file() and ca.is_file()):
        return False, f"no mTLS bundle at {agent_dir}"
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.load_cert_chain(certfile=str(worker_crt), keyfile=str(worker_key))
    ctx.check_hostname = False

    last = ""
    for i in range(attempts):
        try:
            with httpx.Client(verify=ctx, timeout=3.0) as client:
                r = client.get(url)
            if r.status_code == 200:
                return True, r.text
            last = f"status={r.status_code} body={r.text[:200]}"
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"
        if i < attempts - 1:
            time.sleep(backoff_s)
    return False, last


# -------------------------------------------------------------- orchestrator

def _write_manifest(release: pathlib.Path, sha: Optional[str]) -> None:
    import json

    _manifest_file(release).write_text(json.dumps({
        "sha": sha,
        "installed_at": datetime.now(timezone.utc).isoformat(),
    }))


def _rotate(install_dir: pathlib.Path) -> None:
    """Rotate directories: prev→(deleted), active→prev, active.new→active.

    Caller must ensure ``active.new`` exists. ``active`` may or may not.
    """
    active = _active_dir(install_dir)
    prev = _prev_dir(install_dir)
    staging = _staging_dir(install_dir)

    if prev.exists():
        shutil.rmtree(prev)
    if active.exists():
        active.rename(prev)
    staging.rename(active)


def _point_current_at(install_dir: pathlib.Path, target: pathlib.Path) -> None:
    """Atomic symlink flip via rename."""
    link = _current_symlink(install_dir)
    tmp = install_dir / ".current.tmp"
    if tmp.exists() or tmp.is_symlink():
        tmp.unlink()
    tmp.symlink_to(target)
    os.replace(tmp, link)


def run_update(
    tarball_bytes: bytes,
    sha: Optional[str],
    install_dir: pathlib.Path = DEFAULT_INSTALL_DIR,
    agent_dir: pathlib.Path = pki.DEFAULT_AGENT_DIR,
) -> dict[str, Any]:
    """Apply an update atomically. Rolls back on probe failure."""
    clean_stale_staging(install_dir)
    staging = _staging_dir(install_dir)

    extract_tarball(tarball_bytes, staging)
    _write_manifest(staging, sha)

    pip = _run_pip(staging)
    if pip.returncode != 0:
        shutil.rmtree(staging, ignore_errors=True)
        raise UpdateError(
            "pip install failed on new release", stderr=pip.stderr or pip.stdout,
        )

    _rotate(install_dir)
    _point_current_at(install_dir, _active_dir(install_dir))

    _stop_agent(install_dir)
    _spawn_agent(install_dir)

    ok, detail = _probe_agent(agent_dir=agent_dir)
    if ok:
        return {
            "status": "updated",
            "release": read_release(_active_dir(install_dir)).to_dict(),
            "probe": detail,
        }

    # Rollback.
    log.warning("agent probe failed after update: %s — rolling back", detail)
    _stop_agent(install_dir)
    # Swap active <-> prev.
    active = _active_dir(install_dir)
    prev = _prev_dir(install_dir)
    tmp = _releases_dir(install_dir) / ".swap"
    if tmp.exists():
        shutil.rmtree(tmp)
    active.rename(tmp)
    prev.rename(active)
    tmp.rename(prev)
    _point_current_at(install_dir, active)
    _spawn_agent(install_dir)
    ok2, detail2 = _probe_agent(agent_dir=agent_dir)
    raise UpdateError(
        "agent failed health probe after update; rolled back to previous release",
        stderr=f"forward-probe: {detail}\nrollback-probe: {detail2}",
        rolled_back=ok2,
    )


def run_rollback(
    install_dir: pathlib.Path = DEFAULT_INSTALL_DIR,
    agent_dir: pathlib.Path = pki.DEFAULT_AGENT_DIR,
) -> dict[str, Any]:
    """Manually swap active with prev and restart the agent."""
    active = _active_dir(install_dir)
    prev = _prev_dir(install_dir)
    if not prev.is_dir():
        raise UpdateError("no previous release to roll back to")

    _stop_agent(install_dir)
    tmp = _releases_dir(install_dir) / ".swap"
    if tmp.exists():
        shutil.rmtree(tmp)
    active.rename(tmp)
    prev.rename(active)
    tmp.rename(prev)
    _point_current_at(install_dir, active)
    _spawn_agent(install_dir)
    ok, detail = _probe_agent(agent_dir=agent_dir)
    if not ok:
        raise UpdateError("agent unhealthy after rollback", stderr=detail)
    return {
        "status": "rolled_back",
        "release": read_release(active).to_dict(),
        "probe": detail,
    }


def run_update_self(
    tarball_bytes: bytes,
    sha: Optional[str],
    updater_install_dir: pathlib.Path,
    exec_cb: Optional[Callable[[list[str]], None]] = None,
) -> dict[str, Any]:
    """Replace the updater's own source tree, then re-exec this process.

    No auto-rollback. Caller must treat "connection dropped + /health
    returns new SHA within 30s" as success.
    """
    clean_stale_staging(updater_install_dir)
    staging = _staging_dir(updater_install_dir)
    extract_tarball(tarball_bytes, staging)
    _write_manifest(staging, sha)

    pip = _run_pip(staging)
    if pip.returncode != 0:
        shutil.rmtree(staging, ignore_errors=True)
        raise UpdateError(
            "pip install failed on new updater release",
            stderr=pip.stderr or pip.stdout,
        )

    _rotate(updater_install_dir)
    _point_current_at(updater_install_dir, _active_dir(updater_install_dir))

    argv = [str(_venv_python(_active_dir(updater_install_dir))), "-m", "decnet", "updater"] + sys.argv[1:]
    if exec_cb is not None:
        exec_cb(argv)  # tests stub this — we don't actually re-exec
        return {"status": "self_update_queued", "argv": argv}
    # Returns nothing on success (replaces the process image).
    os.execv(argv[0], argv)  # nosec B606 - pragma: no cover
    return {"status": "self_update_queued"}  # pragma: no cover
