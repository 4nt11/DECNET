"""Swarm host lifecycle endpoints: enroll, list, decommission.

Enrollment design
-----------------
The master controller holds the CA private key.  On ``POST /swarm/enroll``
it generates a fresh worker keypair + cert (signed by the master CA) and
returns the full bundle to the operator.  The operator is responsible for
delivering that bundle to the worker's ``~/.decnet/agent/`` directory
(scp/sshpass/ansible — outside this process's trust boundary).

Rationale: the worker agent speaks ONLY mTLS.  There is no pre-auth
bootstrap endpoint, so there is nothing to attack before the worker is
enrolled.  The bundle-delivery step is explicit and auditable.
"""
from __future__ import annotations

import pathlib
import uuid as _uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from decnet.swarm import pki
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo

router = APIRouter(tags=["swarm-hosts"])


# ------------------------------------------------------------------- schemas


class EnrollRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    address: str = Field(..., description="IP or DNS the master uses to reach the worker")
    agent_port: int = Field(default=8765, ge=1, le=65535)
    sans: list[str] = Field(
        default_factory=list,
        description="Extra SANs (IPs / hostnames) to embed in the worker cert",
    )
    notes: Optional[str] = None


class EnrolledBundle(BaseModel):
    """Cert bundle returned to the operator — must be delivered to the worker."""

    host_uuid: str
    name: str
    address: str
    agent_port: int
    fingerprint: str
    ca_cert_pem: str
    worker_cert_pem: str
    worker_key_pem: str


class SwarmHostView(BaseModel):
    uuid: str
    name: str
    address: str
    agent_port: int
    status: str
    last_heartbeat: Optional[datetime] = None
    client_cert_fingerprint: str
    enrolled_at: datetime
    notes: Optional[str] = None


# ------------------------------------------------------------------- routes


@router.post("/enroll", response_model=EnrolledBundle, status_code=status.HTTP_201_CREATED)
async def enroll(
    req: EnrollRequest,
    repo: BaseRepository = Depends(get_repo),
) -> EnrolledBundle:
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

    host_uuid = str(_uuid.uuid4())
    await repo.add_swarm_host(
        {
            "uuid": host_uuid,
            "name": req.name,
            "address": req.address,
            "agent_port": req.agent_port,
            "status": "enrolled",
            "client_cert_fingerprint": issued.fingerprint_sha256,
            "cert_bundle_path": str(bundle_dir),
            "enrolled_at": datetime.now(timezone.utc),
            "notes": req.notes,
        }
    )
    return EnrolledBundle(
        host_uuid=host_uuid,
        name=req.name,
        address=req.address,
        agent_port=req.agent_port,
        fingerprint=issued.fingerprint_sha256,
        ca_cert_pem=issued.ca_cert_pem.decode(),
        worker_cert_pem=issued.cert_pem.decode(),
        worker_key_pem=issued.key_pem.decode(),
    )


@router.get("/hosts", response_model=list[SwarmHostView])
async def list_hosts(
    host_status: Optional[str] = None,
    repo: BaseRepository = Depends(get_repo),
) -> list[SwarmHostView]:
    rows = await repo.list_swarm_hosts(host_status)
    return [SwarmHostView(**r) for r in rows]


@router.get("/hosts/{uuid}", response_model=SwarmHostView)
async def get_host(
    uuid: str,
    repo: BaseRepository = Depends(get_repo),
) -> SwarmHostView:
    row = await repo.get_swarm_host_by_uuid(uuid)
    if row is None:
        raise HTTPException(status_code=404, detail="host not found")
    return SwarmHostView(**row)


@router.delete("/hosts/{uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def decommission(
    uuid: str,
    repo: BaseRepository = Depends(get_repo),
) -> None:
    row = await repo.get_swarm_host_by_uuid(uuid)
    if row is None:
        raise HTTPException(status_code=404, detail="host not found")

    # Remove shard rows first (we own them; cascade is portable via the repo).
    await repo.delete_decky_shards_for_host(uuid)
    await repo.delete_swarm_host(uuid)

    # Best-effort bundle cleanup; if the dir was moved manually, don't fail.
    bundle_dir = pathlib.Path(row.get("cert_bundle_path") or "")
    if bundle_dir.is_dir():
        for child in bundle_dir.iterdir():
            try:
                child.unlink()
            except OSError:
                pass
        try:
            bundle_dir.rmdir()
        except OSError:
            pass
