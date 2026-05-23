# SPDX-License-Identifier: AGPL-3.0-or-later
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
import os
import pathlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from decnet.logging import get_logger
from decnet.swarm import pki
from decnet.swarm.bundle_builder import build_tarball, render_bootstrap
from decnet.web.db.models.swarm import EnrollBundleRequest, EnrollBundleResponse
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

log = get_logger("swarm_mgmt.enroll_bundle")

router = APIRouter()

BUNDLE_TTL = timedelta(minutes=5)
BUNDLE_DIR = pathlib.Path(os.environ.get("DECNET_ENROLL_BUNDLE_DIR", "/tmp/decnet-enroll"))  # nosec B108 - short-lived 0600 bundle cache, env-overridable
SWEEP_INTERVAL_SECS = 30


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


def _now() -> datetime:
    # Indirection so tests can monkeypatch.
    return datetime.now(timezone.utc)


async def _lookup_live(token: str) -> _Bundle:
    b = _BUNDLES.get(token)
    if b is None or b.served or b.expires_at <= _now():
        raise HTTPException(status_code=404, detail="bundle not found or expired")
    return b


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/enroll-bundle",
    response_model=EnrollBundleResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Swarm Management"],
    responses={
        400: {"description": "Bad Request (malformed JSON body)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        409: {"description": "A worker with this name is already enrolled"},
        422: {"description": "Request body validation error"},
    },
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
    tarball = build_tarball(
        req.master_host, req.agent_name, host_uuid, issued, req.services_ini, updater_issued,
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
    script = render_bootstrap(req.agent_name, req.master_host, tarball_url, expires_at, req.with_updater)

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
