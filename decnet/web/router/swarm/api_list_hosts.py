# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /swarm/hosts — list enrolled workers, optionally filtered by status."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends

from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin
from decnet.web.router.swarm._mtls import PeerCert, require_operator_cert
from decnet.web.db.models import SwarmHostView

router = APIRouter()


@router.get(
    "/hosts",
    response_model=list[SwarmHostView],
    tags=["Swarm Hosts"],
    responses={
        401: {"description": "Missing or invalid admin JWT"},
        403: {"description": "Authenticated user is not an admin, or operator cert missing"},
    },
)
async def api_list_hosts(
    host_status: Optional[str] = None,
    repo: BaseRepository = Depends(get_repo),
    _admin: dict = Depends(require_admin),
    _operator: PeerCert = Depends(require_operator_cert),
) -> list[SwarmHostView]:
    rows = await repo.list_swarm_hosts(host_status)
    return [SwarmHostView(**r) for r in rows]
