# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST /swarm-updates/rollback — manual rollback on a single host.

Calls the worker updater's ``/rollback`` which swaps the ``current``
symlink back to ``releases/prev``. Fails with 404 if the target has no
previous release slot.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from decnet.logging import get_logger
from decnet.swarm.updater_client import UpdaterClient
from decnet.web.db.models import RollbackRequest, RollbackResponse
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

log = get_logger("swarm_updates.rollback")

router = APIRouter()


@router.post(
    "/rollback",
    response_model=RollbackResponse,
    tags=["Swarm Updates"],
    responses={
        400: {"description": "Bad Request (malformed JSON body or host has no updater bundle)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Unknown host, or no previous release slot on the worker"},
        422: {"description": "Request body validation error"},
    },
)
async def api_rollback_host(
    req: RollbackRequest,
    admin: dict = Depends(require_admin),
    repo: BaseRepository = Depends(get_repo),
) -> RollbackResponse:
    host = await repo.get_swarm_host_by_uuid(req.host_uuid)
    if host is None:
        raise HTTPException(status_code=404, detail=f"Unknown host: {req.host_uuid}")
    if not host.get("updater_cert_fingerprint"):
        raise HTTPException(
            status_code=400,
            detail=f"Host '{host['name']}' has no updater bundle — nothing to roll back.",
        )

    try:
        async with UpdaterClient(host=host) as u:
            r = await u.rollback()
    except Exception as exc:  # noqa: BLE001
        log.exception("swarm_updates.rollback transport failure host=%s", host["name"])
        return RollbackResponse(
            host_uuid=host["uuid"], host_name=host["name"],
            status="failed",
            detail=f"{type(exc).__name__}: {exc}",
        )

    body = r.json() if r.content else {}
    if r.status_code == 404:
        # No previous release — surface as 404 so the UI can render the
        # "nothing to roll back" state distinctly from a transport error.
        raise HTTPException(
            status_code=404,
            detail=body.get("detail") if isinstance(body, dict) else "No previous release on worker.",
        )
    if r.status_code != 200:
        return RollbackResponse(
            host_uuid=host["uuid"], host_name=host["name"],
            status="failed", http_status=r.status_code,
            detail=(body.get("error") or body.get("detail")) if isinstance(body, dict) else None,
        )
    return RollbackResponse(
        host_uuid=host["uuid"], host_name=host["name"],
        status="rolled-back", http_status=r.status_code,
        detail=body.get("status") if isinstance(body, dict) else None,
    )
