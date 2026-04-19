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


def _shared_venv(install_dir: pathlib.Path) -> pathlib.Path:
    """The one stable venv that agents/updaters run out of.

    Release slots ship source only. We ``pip install --force-reinstall
    --no-deps`` into this venv on promotion so shebangs never dangle
    across a rotation.
    """
    return install_dir / "venv"


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

def _run_pip(
    release: pathlib.Path,
    install_dir: Optional[pathlib.Path] = None,
) -> subprocess.CompletedProcess:
    """pip install ``release`` into the shared venv at ``install_dir/venv``.

    The shared venv is bootstrapped on first use. ``--force-reinstall
    --no-deps`` replaces site-packages for the decnet package only; the
    rest of the env stays cached across updates.

    Monkeypatched in tests so the test suite never shells out.
    """
    idir = install_dir or release.parent.parent  # releases/<slot> -> install_dir
    venv_dir = _shared_venv(idir)
    fresh = not venv_dir.exists()
    if fresh:
        subprocess.run(  # nosec B603
            [sys.executable, "-m", "venv", str(venv_dir)],
            check=True, capture_output=True, text=True,
        )
    py = venv_dir / "bin" / "python"
    # First install into a fresh venv: pull full dep tree. Subsequent updates
    # use --no-deps so pip only replaces the decnet package.
    args = [str(py), "-m", "pip", "install", "--force-reinstall", str(release)]
    if not fresh:
        args.insert(-1, "--no-deps")
    return subprocess.run(  # nosec B603
        args, check=False, capture_output=True, text=True,
    )


def _spawn_agent(install_dir: pathlib.Path) -> int:
    """Launch ``decnet agent --daemon`` using the current-symlinked venv.

    Returns the new PID. Monkeypatched in tests.
    """
    decnet_bin = _shared_venv(install_dir) / "bin" / "decnet"
    log_path = install_dir / "agent.spawn.log"
    # cwd=install_dir so a persistent ``<install_dir>/.env.local`` gets
    # picked up by decnet.env (which loads from CWD). The release slot
    # itself is immutable across updates, so the env file cannot live
    # inside it.
    proc = subprocess.Popen(  # nosec B603
        [str(decnet_bin), "agent", "--daemon"],
        start_new_session=True,
        cwd=str(install_dir),
        stdout=open(log_path, "ab"),  # noqa: SIM115
        stderr=subprocess.STDOUT,
    )
    _pid_file(install_dir).write_text(str(proc.pid))
    return proc.pid


def _discover_agent_pids() -> list[int]:
    """Scan /proc for any running ``decnet agent`` process.

    Used as a fallback when agent.pid is missing (e.g., the agent was started
    by hand rather than by the updater) so an update still produces a clean
    restart instead of leaving the old in-memory code serving requests.
    """
    pids: list[int] = []
    self_pid = os.getpid()
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == self_pid:
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        argv = [a for a in raw.split(b"\x00") if a]
        if len(argv) < 2:
            continue
        if not argv[0].endswith(b"python") and b"python" not in pathlib.Path(argv[0].decode(errors="ignore")).name.encode():
            # Allow direct console-script invocation too: argv[0] ends with /decnet
            if not argv[0].endswith(b"/decnet"):
                continue
        if b"decnet" in b" ".join(argv) and b"agent" in argv:
            pids.append(pid)
    return pids


def _stop_agent(install_dir: pathlib.Path, grace: float = AGENT_RESTART_GRACE_S) -> None:
    """SIGTERM the agent and wait for it to exit; SIGKILL after ``grace`` s.

    Prefers the PID recorded in ``agent.pid`` (processes we spawned) but
    falls back to scanning /proc for any ``decnet agent`` so manually-started
    agents are also restarted cleanly during an update.
    """
    pids: list[int] = []
    pid_file = _pid_file(install_dir)
    if pid_file.is_file():
        try:
            pids.append(int(pid_file.read_text().strip()))
        except (ValueError, OSError):
            pass
    for pid in _discover_agent_pids():
        if pid not in pids:
            pids.append(pid)
    if not pids:
        return
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
    deadline = time.monotonic() + grace
    remaining = list(pids)
    while remaining and time.monotonic() < deadline:
        remaining = [p for p in remaining if _pid_alive(p)]
        if remaining:
            time.sleep(0.2)
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


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
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=str(worker_crt), keyfile=str(worker_key))
    ctx.load_verify_locations(cafile=str(ca))
    ctx.verify_mode = ssl.CERT_REQUIRED
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

    # Reconstruct the updater's original launch command from env vars set by
    # `decnet.updater.server.run`. We can't reuse sys.argv: inside the app
    # process this is the uvicorn subprocess invocation (--ssl-keyfile, etc.),
    # not the operator-visible `decnet updater ...` command.
    decnet_bin = str(_shared_venv(updater_install_dir) / "bin" / "decnet")
    argv = [decnet_bin, "updater",
            "--host", os.environ.get("DECNET_UPDATER_HOST", "0.0.0.0"),  # nosec B104
            "--port", os.environ.get("DECNET_UPDATER_PORT", "8766"),
            "--updater-dir", os.environ.get("DECNET_UPDATER_BUNDLE_DIR",
                                             str(pki.DEFAULT_AGENT_DIR.parent / "updater")),
            "--install-dir", os.environ.get("DECNET_UPDATER_INSTALL_DIR",
                                            str(updater_install_dir.parent)),
            "--agent-dir", os.environ.get("DECNET_UPDATER_AGENT_DIR",
                                          str(pki.DEFAULT_AGENT_DIR))]
    if exec_cb is not None:
        exec_cb(argv)  # tests stub this — we don't actually re-exec
        return {"status": "self_update_queued", "argv": argv}
    # Returns nothing on success (replaces the process image).
    os.execv(argv[0], argv)  # nosec B606 - pragma: no cover
    return {"status": "self_update_queued"}  # pragma: no cover
