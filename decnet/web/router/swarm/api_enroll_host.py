"""POST /swarm/enroll — issue a worker cert bundle and register the host.

Enrollment is master-driven: the controller holds the CA private key,
generates a fresh worker keypair + CA-signed cert, and returns the full
bundle to the operator. Bundle delivery to the worker (scp/sshpass/etc.)
is outside this process's trust boundary.

Rationale: the worker agent speaks ONLY mTLS; there is no pre-auth
bootstrap endpoint, so nothing to attack before the worker is enrolled.
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status

from decnet.swarm import pki
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo
from decnet.web.db.models import SwarmEnrolledBundle, SwarmEnrollRequest, SwarmUpdaterBundle

router = APIRouter()


@router.post(
    "/enroll",
    response_model=SwarmEnrolledBundle,
    status_code=status.HTTP_201_CREATED,
    tags=["Swarm Hosts"],
)
async def api_enroll_host(
    req: SwarmEnrollRequest,
    repo: BaseRepository = Depends(get_repo),
) -> SwarmEnrolledBundle:
    existing = await repo.get_swarm_host_by_name(req.name)
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Worker '{req.name}' is already enrolled")

    ca = pki.ensure_ca()
    sans = list({*req.sans, req.address, req.name})
    issued = pki.issue_worker_cert(ca, req.name, sans)

    # Persist the bundle under ~/.decnet/ca/workers/<name>/ so the master
    # can replay it if the operator loses the original delivery.
    bundle_dir = pki.DEFAULT_CA_DIR / "workers" / req.name
    pki.write_worker_bundle(issued, bundle_dir)

    updater_view: Optional[SwarmUpdaterBundle] = None
    updater_fp: Optional[str] = None
    if req.issue_updater_bundle:
        updater_cn = f"updater@{req.name}"
        updater_sans = list({*sans, updater_cn, "127.0.0.1"})
        updater_issued = pki.issue_worker_cert(ca, updater_cn, updater_sans)
        # Persist alongside the worker bundle for replay.
        updater_dir = bundle_dir / "updater"
        updater_dir.mkdir(parents=True, exist_ok=True)
        (updater_dir / "updater.crt").write_bytes(updater_issued.cert_pem)
        (updater_dir / "updater.key").write_bytes(updater_issued.key_pem)
        import os as _os
        _os.chmod(updater_dir / "updater.key", 0o600)
        updater_fp = updater_issued.fingerprint_sha256
        updater_view = SwarmUpdaterBundle(
            fingerprint=updater_fp,
            updater_cert_pem=updater_issued.cert_pem.decode(),
            updater_key_pem=updater_issued.key_pem.decode(),
        )

    host_uuid = str(_uuid.uuid4())
    await repo.add_swarm_host(
        {
            "uuid": host_uuid,
            "name": req.name,
            "address": req.address,
            "agent_port": req.agent_port,
            "status": "enrolled",
            "client_cert_fingerprint": issued.fingerprint_sha256,
            "updater_cert_fingerprint": updater_fp,
            "cert_bundle_path": str(bundle_dir),
            "enrolled_at": datetime.now(timezone.utc),
            "notes": req.notes,
        }
    )
    return SwarmEnrolledBundle(
        host_uuid=host_uuid,
        name=req.name,
        address=req.address,
        agent_port=req.agent_port,
        fingerprint=issued.fingerprint_sha256,
        ca_cert_pem=issued.ca_cert_pem.decode(),
        worker_cert_pem=issued.cert_pem.decode(),
        worker_key_pem=issued.key_pem.decode(),
        updater=updater_view,
    )
