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
from decnet.web.dependencies import get_repo
from decnet.web.db.models import SwarmCheckResponse, SwarmHostHealth

log = get_logger("swarm.check")

router = APIRouter()


@router.post("/check", response_model=SwarmCheckResponse, tags=["Swarm Health"])
async def api_check_hosts(
    repo: BaseRepository = Depends(get_repo),
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
            log.warning("swarm.check unreachable host=%s err=%s", host["name"], exc)
            await repo.update_swarm_host(host["uuid"], {"status": "unreachable"})
            return SwarmHostHealth(
                host_uuid=host["uuid"],
                name=host["name"],
                address=host["address"],
                reachable=False,
                detail=str(exc),
            )

    results = await asyncio.gather(*(_probe(h) for h in hosts))
    return SwarmCheckResponse(results=list(results))
