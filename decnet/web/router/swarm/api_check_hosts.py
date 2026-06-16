# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST /swarm/check — active mTLS probe of every enrolled worker.

Updates ``SwarmHost.status`` and ``last_heartbeat`` for each host based
on the outcome of the probe.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends

from decnet.logging import get_logger
from decnet.swarm.client import AgentClient
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin
from decnet.web.router.swarm._mtls import PeerCert, require_operator_cert
from decnet.web.db.models import SwarmCheckResponse, SwarmHostHealth

log = get_logger("swarm.check")

router = APIRouter()


@router.post(
    "/check",
    response_model=SwarmCheckResponse,
    tags=["Swarm Health"],
    responses={
        401: {"description": "Missing or invalid admin JWT"},
        403: {"description": "Authenticated user is not an admin, or operator cert missing"},
    },
)
async def api_check_hosts(
    repo: BaseRepository = Depends(get_repo),
    _admin: dict = Depends(require_admin),
    _operator: PeerCert = Depends(require_operator_cert),
) -> SwarmCheckResponse:
    hosts = await repo.list_swarm_hosts()

    async def _probe(host: dict[str, Any]) -> SwarmHostHealth:
        try:
            async with AgentClient(host=host) as agent:
                body = await agent.health()
            await repo.update_swarm_host(
                host["uuid"],
                {
                    "status": "active",
                    "last_heartbeat": datetime.now(timezone.utc),
                },
            )
            return SwarmHostHealth(
                host_uuid=host["uuid"],
                name=host["name"],
                address=host["address"],
                reachable=True,
                detail=body,
            )
        except Exception as exc:
            # Log the real exception server-side; never surface internal
            # exception text (file paths, TLS internals, library guts) to the
            # caller. Same fail-closed posture as the global 500 handler.
            log.warning("swarm.check unreachable host=%s err=%s", host["name"], exc)
            await repo.update_swarm_host(host["uuid"], {"status": "unreachable"})
            return SwarmHostHealth(
                host_uuid=host["uuid"],
                name=host["name"],
                address=host["address"],
                reachable=False,
                detail="probe failed",
            )

    results = await asyncio.gather(*(_probe(h) for h in hosts))
    return SwarmCheckResponse(results=list(results))
