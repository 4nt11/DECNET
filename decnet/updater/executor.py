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
import hashlib
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

# Hard cap on the post-decompression size of an update tarball. The DECNET
# source tree is on the order of single-digit MiB; 256 MiB is far above
# that but small enough to bound damage from a gzip bomb. mTLS already
# authenticates the master, but the worker still treats the bytes as
# untrusted because (a) a compromised master shouldn't get arbitrary RAM
# exhaustion on every agent, (b) bugs in the master tarball builder
# shouldn't brick agents.
MAX_TARBALL_UNCOMPRESSED_BYTES = 256 * 1024 * 1024


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


def _heal_path_symlink(install_dir: pathlib.Path) -> None:
    """Point /usr/local/bin/decnet at the shared venv we manage.

    Pre-fix bootstraps installed into ``<install_dir>/.venv`` (editable) and
    symlinked /usr/local/bin/decnet there, so systemd units kept executing
    the pre-update code even after ``_run_pip`` wrote to the shared venv.
    Fix it opportunistically on every update so already-enrolled hosts
    recover on the next push instead of needing a manual re-enroll.
    """
    target = _shared_venv(install_dir) / "bin" / "decnet"
    link = pathlib.Path("/usr/local/bin/decnet")
    if not target.is_file():
        return
    try:
        if link.is_symlink() and pathlib.Path(os.readlink(link)) == target:
            return
        tmp = link.with_suffix(".tmp")
        if tmp.exists() or tmp.is_symlink():
            tmp.unlink()
        tmp.symlink_to(target)
        os.replace(tmp, link)
        log.info("repointed %s -> %s", link, target)
    except OSError as exc:
        log.warning("could not repoint %s: %s", link, exc)


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

    Hardening on top of stdlib ``tarfile``:

    * Rejects absolute paths and ``..`` traversal in member names.
    * Rejects anything that isn't a regular file or directory — no symlinks,
      hardlinks, devices, or FIFOs. A symlink pointing outside ``dest``
      would let later writes (pip install, etc.) escape the staging tree.
    * Validates that each member's *resolved* destination path stays under
      ``dest`` after symlink resolution, in case a parent directory in the
      tarball is itself a symlink we missed.
    * Caps total uncompressed size to bound gzip-bomb damage.
    * Strips suid/sgid bits from extracted file modes.
    """
    import io

    dest.mkdir(parents=True, exist_ok=False)
    dest_resolved = dest.resolve()
    total_size = 0
    with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            name = member.name
            if name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts:
                raise UpdateError(f"unsafe path in tarball: {name!r}")
            if not (member.isfile() or member.isdir()):
                raise UpdateError(
                    f"unsupported tar entry {name!r}: type={member.type!r}; "
                    "only regular files and directories are allowed"
                )
            total_size += max(member.size, 0)
            if total_size > MAX_TARBALL_UNCOMPRESSED_BYTES:
                raise UpdateError(
                    f"tarball exceeds size cap "
                    f"({total_size} > {MAX_TARBALL_UNCOMPRESSED_BYTES} bytes)"
                )
            # Strip setuid/setgid/sticky bits — extracted files should never
            # acquire elevated mode, even if the master built the tarball
            # against a tree that has them by accident.
            member.mode = member.mode & 0o777 & ~0o7000
        for member in members:
            target = (dest / member.name).resolve()
            try:
                target.relative_to(dest_resolved)
            except ValueError:
                raise UpdateError(
                    f"resolved path escapes dest: {member.name!r} -> {target}"
                ) from None
        tar.extractall(dest)  # nosec B202 — every member validated above


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


AGENT_SYSTEMD_UNIT = "decnet-agent.service"
FORWARDER_SYSTEMD_UNIT = "decnet-forwarder.service"
UPDATER_SYSTEMD_UNIT = "decnet-updater.service"
# Per-host microservices that run out of the same /opt/decnet tree. An
# update replaces their code, so we must cycle them alongside the agent or
# they keep serving the pre-update image. Best-effort: legacy enrollments
# without these units installed shouldn't abort the update.
AUXILIARY_SYSTEMD_UNITS = (
    "decnet-collector.service", "decnet-prober.service",
    "decnet-sniffer.service",
)


def _systemd_available() -> bool:
    """True when we're running under systemd and have systemctl on PATH.

    Detection is conservative: we only return True if *both* the invocation
    marker is set (``INVOCATION_ID`` is exported by systemd for every unit)
    and ``systemctl`` is resolvable. The env var alone can be forged; the
    binary alone can exist on hosts running other init systems.
    """
    if not os.environ.get("INVOCATION_ID"):
        return False
    from shutil import which
    return which("systemctl") is not None


def _spawn_agent(install_dir: pathlib.Path) -> int:
    """Launch the agent and return its PID.

    Under systemd, restart ``decnet-agent.service`` via ``systemctl`` so the
    new process inherits the unit's ambient capabilities (CAP_NET_ADMIN,
    CAP_NET_RAW). Spawning with ``subprocess.Popen`` from inside the updater
    unit would make the agent a child of the updater and therefore a member
    of the updater's (empty) capability set — it would come up without the
    caps needed to run MACVLAN/scapy.

    Off systemd (dev boxes, manual starts), fall back to a direct Popen.
    """
    if _systemd_available():
        return _spawn_agent_via_systemd(install_dir)
    return _spawn_agent_via_popen(install_dir)


SYSTEMD_UNIT_DIR = pathlib.Path("/etc/systemd/system")


def _sync_systemd_units(
    install_dir: pathlib.Path,
    dst_root: pathlib.Path = SYSTEMD_UNIT_DIR,
) -> bool:
    """Copy any `etc/systemd/system/*.service` files from the active release
    into ``dst_root`` (default ``/etc/systemd/system/``) and run
    `daemon-reload` if anything changed.

    Returns True if daemon-reload was invoked. The bootstrap installer writes
    these files on first enrollment; the updater mirrors that on every code
    push so unit edits (ExecStart flips, new units, cap changes) ship too.
    Best-effort: a read-only /etc or a missing ``active/etc`` subtree is just
    logged and skipped.
    """
    src_root = _active_dir(install_dir) / "etc" / "systemd" / "system"
    if not src_root.is_dir():
        return False
    changed = False
    for src in sorted(src_root.glob("*.service")):
        dst = dst_root / src.name
        try:
            new = src.read_bytes()
            old = dst.read_bytes() if dst.is_file() else None
            if old == new:
                continue
            tmp = dst.with_suffix(".service.tmp")
            tmp.write_bytes(new)
            os.chmod(tmp, 0o644)
            os.replace(tmp, dst)
            log.info("installed/updated systemd unit %s", dst)
            changed = True
        except OSError as exc:
            log.warning("could not install unit %s: %s", dst, exc)
    if changed and _systemd_available():
        try:
            subprocess.run(  # nosec B603 B607
                ["systemctl", "daemon-reload"],
                check=True, capture_output=True, text=True,
            )
            log.info("systemctl daemon-reload succeeded")
        except subprocess.CalledProcessError as exc:
            log.warning("systemctl daemon-reload failed: %s", exc.stderr.strip())
    return changed


def _spawn_agent_via_systemd(install_dir: pathlib.Path) -> int:
    # Restart agent + forwarder together: both processes run out of the same
    # /opt/decnet tree, so a code push that replaces the tree must cycle both
    # or the forwarder keeps the pre-update code in memory. Forwarder restart
    # is best-effort — a worker without the forwarder unit installed (e.g. a
    # legacy enrollment) shouldn't abort the update.
    subprocess.run(  # nosec B603 B607
        ["systemctl", "restart", AGENT_SYSTEMD_UNIT],
        check=True, capture_output=True, text=True,
    )
    fwd = subprocess.run(  # nosec B603 B607
        ["systemctl", "restart", FORWARDER_SYSTEMD_UNIT],
        check=False, capture_output=True, text=True,
    )
    if fwd.returncode != 0:
        log.warning("forwarder restart failed (ignored): %s", fwd.stderr.strip())
    for unit in AUXILIARY_SYSTEMD_UNITS:
        aux = subprocess.run(  # nosec B603 B607
            ["systemctl", "restart", unit],
            check=False, capture_output=True, text=True,
        )
        if aux.returncode != 0:
            log.warning("%s restart failed (ignored): %s", unit, aux.stderr.strip())
    pid_out = subprocess.run(  # nosec B603 B607
        ["systemctl", "show", "--property=MainPID", "--value", AGENT_SYSTEMD_UNIT],
        check=True, capture_output=True, text=True,
    )
    pid = int(pid_out.stdout.strip() or "0")
    if pid:
        _pid_file(install_dir).write_text(str(pid))
    return pid


def _spawn_agent_via_popen(install_dir: pathlib.Path) -> int:
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

    Under systemd, stop is a no-op — ``_spawn_agent`` issues a single
    ``systemctl restart`` that handles stop and start atomically. Pre-stopping
    would only race the restart's own stop phase.
    """
    if _systemd_available():
        return
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


def _verify_tarball_sha256(tarball_bytes: bytes, expected_sha256: Optional[str]) -> None:
    """Refuse to extract a tarball whose SHA-256 disagrees with the operator-supplied digest.

    mTLS already authenticates the master, so a network MITM can't forge
    bytes. This check exists for two narrower cases: catching corruption
    in transit (proxies, broken disks) before we explode a half-decoded
    archive into the staging tree, and giving the operator a way to pin
    "exactly these bytes" when distributing a vetted release. The form
    field is optional — if the caller doesn't send one, we skip the
    check rather than reject (no breaking change for older masters).
    """
    if not expected_sha256:
        return
    expected = expected_sha256.strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise UpdateError(f"sha256 digest is not a 64-char hex string: {expected_sha256!r}")
    actual = hashlib.sha256(tarball_bytes).hexdigest()
    if actual != expected:
        raise UpdateError(
            f"tarball sha256 mismatch (expected={expected[:16]}…, got={actual[:16]}…)"
        )


def run_update(
    tarball_bytes: bytes,
    sha: Optional[str],
    install_dir: pathlib.Path = DEFAULT_INSTALL_DIR,
    agent_dir: pathlib.Path = pki.DEFAULT_AGENT_DIR,
    expected_sha256: Optional[str] = None,
) -> dict[str, Any]:
    """Apply an update atomically. Rolls back on probe failure."""
    log.info("update received sha=%s bytes=%d install_dir=%s", sha, len(tarball_bytes), install_dir)
    _verify_tarball_sha256(tarball_bytes, expected_sha256)
    clean_stale_staging(install_dir)
    staging = _staging_dir(install_dir)

    log.info("extracting tarball -> %s", staging)
    extract_tarball(tarball_bytes, staging)
    _write_manifest(staging, sha)

    log.info("pip install into shared venv (%s)", _shared_venv(install_dir))
    pip = _run_pip(staging)
    if pip.returncode != 0:
        log.error("pip install failed rc=%d stderr=%s", pip.returncode, (pip.stderr or pip.stdout).strip()[:400])
        shutil.rmtree(staging, ignore_errors=True)
        raise UpdateError(
            "pip install failed on new release", stderr=pip.stderr or pip.stdout,
        )

    log.info("rotating releases: active.new -> active, active -> prev")
    _rotate(install_dir)
    _point_current_at(install_dir, _active_dir(install_dir))
    _heal_path_symlink(install_dir)
    _sync_systemd_units(install_dir)

    log.info("restarting agent (and forwarder if present)")
    _stop_agent(install_dir)
    _spawn_agent(install_dir)

    ok, detail = _probe_agent(agent_dir=agent_dir)
    if ok:
        log.info("update complete sha=%s probe=ok", sha)
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
    expected_sha256: Optional[str] = None,
) -> dict[str, Any]:
    """Replace the updater's own source tree, then re-exec this process.

    No auto-rollback. Caller must treat "connection dropped + /health
    returns new SHA within 30s" as success.
    """
    log.info("self-update received sha=%s bytes=%d install_dir=%s", sha, len(tarball_bytes), updater_install_dir)
    _verify_tarball_sha256(tarball_bytes, expected_sha256)
    clean_stale_staging(updater_install_dir)
    staging = _staging_dir(updater_install_dir)
    log.info("extracting tarball -> %s", staging)
    extract_tarball(tarball_bytes, staging)
    _write_manifest(staging, sha)

    log.info("pip install updater release into shared venv (%s)", _shared_venv(updater_install_dir))
    pip = _run_pip(staging)
    if pip.returncode != 0:
        log.error("self-update pip install failed rc=%d stderr=%s", pip.returncode, (pip.stderr or pip.stdout).strip()[:400])
        shutil.rmtree(staging, ignore_errors=True)
        raise UpdateError(
            "pip install failed on new updater release",
            stderr=pip.stderr or pip.stdout,
        )

    log.info("rotating updater releases and flipping current symlink")
    _rotate(updater_install_dir)
    _point_current_at(updater_install_dir, _active_dir(updater_install_dir))
    _heal_path_symlink(updater_install_dir)
    _sync_systemd_units(updater_install_dir)

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
    # Under systemd, hand the restart to the init system so the new process
    # keeps its unit context (capabilities, cgroup, logging target) instead
    # of inheriting whatever we had here. Spawn a detached sh that waits for
    # this response to flush before issuing the restart — `systemctl restart`
    # on our own unit would kill us mid-response and the caller would see a
    # connection drop with no indication of success.
    if _systemd_available():
        log.info("self-update queued: systemctl restart %s (deferred 1s)", UPDATER_SYSTEMD_UNIT)
        subprocess.Popen(  # nosec B603 B607
            ["sh", "-c", f"sleep 1 && systemctl restart {UPDATER_SYSTEMD_UNIT}"],
            start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return {"status": "self_update_queued", "via": "systemd"}
    # Off-systemd fallback: replace the process image directly.
    os.execv(argv[0], argv)  # nosec B606 - pragma: no cover
    return {"status": "self_update_queued"}  # pragma: no cover
