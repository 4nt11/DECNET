"""Agent-enrollment bundles — the Wazuh-style one-liner flow.

Three endpoints:
  POST /swarm/enroll-bundle          — admin issues certs + builds payload
  GET  /swarm/enroll-bundle/{t}.sh   — bootstrap script (idempotent until .tgz)
  GET  /swarm/enroll-bundle/{t}.tgz  — tarball payload (one-shot; trips served)

The operator's paste is a single pipe ``curl -fsSL <.sh> | sudo bash``.
Under the hood the bootstrap curls the ``.tgz`` from the same token.
Both files are rendered + persisted on POST; the ``.tgz`` GET atomically
marks the token served, reads the bytes under the lock, and unlinks both
files so a sweeper cannot race it. Unclaimed tokens expire after 5 min.

We avoid the single-self-extracting-script pattern because ``bash`` run
via pipe has ``$0 == "bash"`` — there is no file on disk to ``tail`` for
the embedded payload. Two URLs, one paste.
"""
from __future__ import annotations

import asyncio
import fnmatch
import io
import os
import pathlib
import secrets
import tarfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from decnet.logging import get_logger
from decnet.swarm import pki
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

log = get_logger("swarm_mgmt.enroll_bundle")

router = APIRouter()

BUNDLE_TTL = timedelta(minutes=5)
BUNDLE_DIR = pathlib.Path(os.environ.get("DECNET_ENROLL_BUNDLE_DIR", "/tmp/decnet-enroll"))  # nosec B108 - short-lived 0600 bundle cache, env-overridable
SWEEP_INTERVAL_SECS = 30

# Paths excluded from the bundled tarball. Matches the intent of
# decnet.swarm.tar_tree.DEFAULT_EXCLUDES but narrower — we never want
# tests, dev scaffolding, the master's DB, or the frontend source tree
# shipped to an agent.
_EXCLUDES: tuple[str, ...] = (
    ".venv", ".venv/*", "**/.venv/*",
    "__pycache__", "**/__pycache__", "**/__pycache__/*",
    ".git", ".git/*",
    ".pytest_cache", ".pytest_cache/*",
    ".mypy_cache", ".mypy_cache/*",
    "*.egg-info", "*.egg-info/*",
    "*.pyc", "*.pyo",
    "*.db", "*.db-wal", "*.db-shm", "decnet.db*",
    "*.log",
    "tests", "tests/*",
    "development", "development/*",
    "wiki-checkout", "wiki-checkout/*",
    "decnet_web/node_modules", "decnet_web/node_modules/*",
    "decnet_web/src", "decnet_web/src/*",
    "decnet-state.json",
    "master.log", "master.json",
    "decnet.tar",
    # Dev-host env/config leaks — these bake the master's absolute paths into
    # the agent and point log handlers at directories that don't exist on the
    # worker VM.
    ".env", ".env.*", "**/.env", "**/.env.*",
    "decnet.ini", "**/decnet.ini",
)


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------

class EnrollBundleRequest(BaseModel):
    master_host: str = Field(..., min_length=1, max_length=253,
                             description="IP/host the agent will reach back to")
    agent_name: str = Field(..., pattern=r"^[a-z0-9][a-z0-9-]{0,62}$",
                            description="Worker name (DNS-label safe)")
    with_updater: bool = Field(
        default=True,
        description="Include updater cert bundle and auto-start decnet updater on the agent",
    )
    use_ipvlan: bool = Field(
        default=False,
        description=(
            "Run deckies on this agent over IPvlan L2 instead of MACVLAN. "
            "Required when the agent is a VirtualBox/VMware guest bridged over Wi-Fi — "
            "Wi-Fi APs bind one MAC per station, so MACVLAN's extra container MACs "
            "rotate the VM's DHCP lease. Safe no-op on wired/bare-metal hosts."
        ),
    )
    services_ini: Optional[str] = Field(
        default=None,
        description="Optional INI text shipped to the agent as /etc/decnet/services.ini",
    )


class EnrollBundleResponse(BaseModel):
    token: str
    command: str
    expires_at: datetime
    host_uuid: str


# ---------------------------------------------------------------------------
# In-memory registry
# ---------------------------------------------------------------------------

@dataclass
class _Bundle:
    sh_path: pathlib.Path
    tgz_path: pathlib.Path
    expires_at: datetime
    host_uuid: str
    served: bool = False


_BUNDLES: dict[str, _Bundle] = {}
_LOCK = asyncio.Lock()
_SWEEPER_TASK: Optional[asyncio.Task] = None


async def _sweep_loop() -> None:
    while True:
        try:
            await asyncio.sleep(SWEEP_INTERVAL_SECS)
            now = datetime.now(timezone.utc)
            async with _LOCK:
                dead = [t for t, b in _BUNDLES.items() if b.served or b.expires_at <= now]
                for t in dead:
                    b = _BUNDLES.pop(t)
                    for p in (b.sh_path, b.tgz_path):
                        try:
                            p.unlink()
                        except FileNotFoundError:
                            pass
                        except OSError as exc:
                            log.warning("enroll-bundle sweep unlink failed path=%s err=%s", p, exc)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("enroll-bundle sweeper iteration failed")


def _ensure_sweeper() -> None:
    global _SWEEPER_TASK
    if _SWEEPER_TASK is None or _SWEEPER_TASK.done():
        _SWEEPER_TASK = asyncio.create_task(_sweep_loop())


# ---------------------------------------------------------------------------
# Tarball construction
# ---------------------------------------------------------------------------

def _repo_root() -> pathlib.Path:
    # decnet/web/router/swarm_mgmt/api_enroll_bundle.py -> 4 parents = repo root.
    return pathlib.Path(__file__).resolve().parents[4]


def _is_excluded(rel: str) -> bool:
    parts = pathlib.PurePosixPath(rel).parts
    for pat in _EXCLUDES:
        if fnmatch.fnmatch(rel, pat):
            return True
        for i in range(1, len(parts) + 1):
            if fnmatch.fnmatch("/".join(parts[:i]), pat):
                return True
    return False


def _render_decnet_ini(master_host: str, use_ipvlan: bool = False) -> bytes:
    ipvlan_line = f"ipvlan = {'true' if use_ipvlan else 'false'}\n"
    return (
        "; Generated by DECNET agent-enrollment bundle.\n"
        "[decnet]\n"
        "mode = agent\n"
        "disallow-master = true\n"
        "log-directory = /var/log/decnet\n"
        f"{ipvlan_line}"
        "\n"
        "[agent]\n"
        f"master-host = {master_host}\n"
        "swarm-syslog-port = 6514\n"
        "agent-port = 8765\n"
        "agent-dir = /etc/decnet/agent\n"
        "updater-dir = /etc/decnet/updater\n"
    ).encode()


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(datetime.now(timezone.utc).timestamp())
    tar.addfile(info, io.BytesIO(data))


def _build_tarball(
    master_host: str,
    agent_name: str,
    issued: pki.IssuedCert,
    services_ini: Optional[str],
    updater_issued: Optional[pki.IssuedCert] = None,
    use_ipvlan: bool = False,
) -> bytes:
    """Gzipped tarball with:
      - full repo source (minus excludes)
      - etc/decnet/decnet.ini (pre-baked for mode=agent)
      - home/.decnet/agent/{ca.crt,worker.crt,worker.key}
      - home/.decnet/updater/{ca.crt,updater.crt,updater.key}  (if updater_issued)
      - services.ini at root if provided
    """
    root = _repo_root()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root).as_posix()
            if _is_excluded(rel):
                continue
            if path.is_symlink() or path.is_dir():
                continue
            tar.add(path, arcname=rel, recursive=False)

        _add_bytes(tar, "etc/decnet/decnet.ini", _render_decnet_ini(master_host, use_ipvlan))
        for unit in _SYSTEMD_UNITS:
            _add_bytes(
                tar,
                f"etc/systemd/system/{unit}.service",
                _render_systemd_unit(unit, agent_name, master_host),
            )
        _add_bytes(tar, "home/.decnet/agent/ca.crt", issued.ca_cert_pem)
        _add_bytes(tar, "home/.decnet/agent/worker.crt", issued.cert_pem)
        _add_bytes(tar, "home/.decnet/agent/worker.key", issued.key_pem, mode=0o600)

        if updater_issued is not None:
            _add_bytes(tar, "home/.decnet/updater/ca.crt", updater_issued.ca_cert_pem)
            _add_bytes(tar, "home/.decnet/updater/updater.crt", updater_issued.cert_pem)
            _add_bytes(tar, "home/.decnet/updater/updater.key", updater_issued.key_pem, mode=0o600)

        if services_ini:
            _add_bytes(tar, "services.ini", services_ini.encode())

    return buf.getvalue()


_SYSTEMD_UNITS = ("decnet-agent", "decnet-forwarder", "decnet-engine")


def _render_systemd_unit(name: str, agent_name: str, master_host: str) -> bytes:
    tpl_path = pathlib.Path(__file__).resolve().parents[1].parent / "templates" / f"{name}.service.j2"
    tpl = tpl_path.read_text()
    return (
        tpl.replace("{{ agent_name }}", agent_name)
           .replace("{{ master_host }}", master_host)
    ).encode()


def _render_bootstrap(
    agent_name: str,
    master_host: str,
    tarball_url: str,
    expires_at: datetime,
    with_updater: bool,
) -> bytes:
    tpl_path = pathlib.Path(__file__).resolve().parents[1].parent / "templates" / "enroll_bootstrap.sh.j2"
    tpl = tpl_path.read_text()
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    rendered = (
        tpl.replace("{{ agent_name }}", agent_name)
           .replace("{{ master_host }}", master_host)
           .replace("{{ tarball_url }}", tarball_url)
           .replace("{{ generated_at }}", now)
           .replace("{{ expires_at }}", expires_at.replace(microsecond=0).isoformat())
           .replace("{{ with_updater }}", "true" if with_updater else "false")
    )
    return rendered.encode()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/enroll-bundle",
    response_model=EnrollBundleResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Swarm Management"],
)
async def create_enroll_bundle(
    req: EnrollBundleRequest,
    request: Request,
    admin: dict = Depends(require_admin),
    repo: BaseRepository = Depends(get_repo),
) -> EnrollBundleResponse:
    import uuid as _uuid

    existing = await repo.get_swarm_host_by_name(req.agent_name)
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Worker '{req.agent_name}' is already enrolled")

    # 1. Issue certs (reuses the same code as /swarm/enroll). The worker's own
    # address is not known yet — the master learns it when the agent fetches
    # the tarball (see get_payload), which also backfills the SwarmHost row.
    ca = pki.ensure_ca()
    sans = list({req.agent_name, req.master_host})
    issued = pki.issue_worker_cert(ca, req.agent_name, sans)
    bundle_dir = pki.DEFAULT_CA_DIR / "workers" / req.agent_name
    pki.write_worker_bundle(issued, bundle_dir)

    updater_issued: Optional[pki.IssuedCert] = None
    updater_fp: Optional[str] = None
    if req.with_updater:
        updater_cn = f"updater@{req.agent_name}"
        updater_sans = list({*sans, updater_cn, "127.0.0.1"})
        updater_issued = pki.issue_worker_cert(ca, updater_cn, updater_sans)
        updater_dir = bundle_dir / "updater"
        updater_dir.mkdir(parents=True, exist_ok=True)
        (updater_dir / "updater.crt").write_bytes(updater_issued.cert_pem)
        (updater_dir / "updater.key").write_bytes(updater_issued.key_pem)
        os.chmod(updater_dir / "updater.key", 0o600)
        updater_fp = updater_issued.fingerprint_sha256

    # 2. Register the host row so it shows up in SwarmHosts immediately.
    host_uuid = str(_uuid.uuid4())
    await repo.add_swarm_host(
        {
            "uuid": host_uuid,
            "name": req.agent_name,
            "address": "",  # filled in when the agent fetches the .tgz (its source IP)
            "agent_port": 8765,
            "status": "enrolled",
            "client_cert_fingerprint": issued.fingerprint_sha256,
            "updater_cert_fingerprint": updater_fp,
            "cert_bundle_path": str(bundle_dir),
            "enrolled_at": datetime.now(timezone.utc),
            "notes": "enrolled via UI bundle",
            "use_ipvlan": req.use_ipvlan,
        }
    )

    # 3. Render payload + bootstrap.
    tarball = _build_tarball(
        req.master_host, req.agent_name, issued, req.services_ini, updater_issued,
        use_ipvlan=req.use_ipvlan,
    )
    token = secrets.token_urlsafe(24)
    expires_at = datetime.now(timezone.utc) + BUNDLE_TTL

    BUNDLE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    sh_path = BUNDLE_DIR / f"{token}.sh"
    tgz_path = BUNDLE_DIR / f"{token}.tgz"

    # Build URLs against the operator-supplied master_host (reachable from the
    # new agent) rather than request.base_url, which reflects how the dashboard
    # user reached us — often 127.0.0.1 behind a proxy or loopback-bound API.
    scheme = request.url.scheme
    port = request.url.port
    netloc = req.master_host if port is None else f"{req.master_host}:{port}"
    base = f"{scheme}://{netloc}"
    tarball_url = f"{base}/api/v1/swarm/enroll-bundle/{token}.tgz"
    bootstrap_url = f"{base}/api/v1/swarm/enroll-bundle/{token}.sh"
    script = _render_bootstrap(req.agent_name, req.master_host, tarball_url, expires_at, req.with_updater)

    tgz_path.write_bytes(tarball)
    sh_path.write_bytes(script)
    os.chmod(tgz_path, 0o600)
    os.chmod(sh_path, 0o600)

    async with _LOCK:
        _BUNDLES[token] = _Bundle(
            sh_path=sh_path, tgz_path=tgz_path, expires_at=expires_at, host_uuid=host_uuid,
        )
    _ensure_sweeper()

    log.info("enroll-bundle created agent=%s master=%s token=%s...", req.agent_name, req.master_host, token[:8])

    return EnrollBundleResponse(
        token=token,
        command=f"curl -fsSL {bootstrap_url} | sudo bash",
        expires_at=expires_at,
        host_uuid=host_uuid,
    )


def _now() -> datetime:
    # Indirection so tests can monkeypatch.
    return datetime.now(timezone.utc)


async def _lookup_live(token: str) -> _Bundle:
    b = _BUNDLES.get(token)
    if b is None or b.served or b.expires_at <= _now():
        raise HTTPException(status_code=404, detail="bundle not found or expired")
    return b


@router.get(
    "/enroll-bundle/{token}.sh",
    tags=["Swarm Management"],
    include_in_schema=False,
)
async def get_bootstrap(token: str) -> Response:
    async with _LOCK:
        b = await _lookup_live(token)
        data = b.sh_path.read_bytes()
    return Response(content=data, media_type="text/x-shellscript")


@router.get(
    "/enroll-bundle/{token}.tgz",
    tags=["Swarm Management"],
    include_in_schema=False,
)
async def get_payload(
    token: str,
    request: Request,
    repo: BaseRepository = Depends(get_repo),
) -> Response:
    async with _LOCK:
        b = await _lookup_live(token)
        b.served = True
        data = b.tgz_path.read_bytes()
        host_uuid = b.host_uuid
        for p in (b.sh_path, b.tgz_path):
            try:
                p.unlink()
            except FileNotFoundError:
                pass

    # The agent's first connect-back — its source IP is the reachable address
    # the master will later use to probe it. Backfill the SwarmHost row here
    # so the operator sees the real address instead of an empty placeholder.
    client_host = request.client.host if request.client else ""
    if client_host:
        try:
            await repo.update_swarm_host(host_uuid, {"address": client_host})
        except Exception as e:  # noqa: BLE001
            log.warning("enroll-bundle could not backfill address host=%s err=%s", host_uuid, e)

    return Response(content=data, media_type="application/gzip")
