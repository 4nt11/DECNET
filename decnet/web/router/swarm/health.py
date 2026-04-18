"""Health endpoints for the swarm controller.

* ``GET /swarm/health``  — liveness of the controller itself (no I/O).
* ``POST /swarm/check``  — active probe of every enrolled worker over mTLS.
  Updates ``SwarmHost.status`` and ``last_heartbeat``.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from decnet.logging import get_logger
from decnet.swarm.client import AgentClient
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo

log = get_logger("swarm.health")

router = APIRouter(tags=["swarm-health"])


class HostHealth(BaseModel):
    host_uuid: str
    name: str
    address: str
    reachable: bool
    detail: Any | None = None


class CheckResponse(BaseModel):
    results: list[HostHealth]


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "role": "swarm-controller"}


@router.post("/check", response_model=CheckResponse)
async def check(
    repo: BaseRepository = Depends(get_repo),
) -> CheckResponse:
    hosts = await repo.list_swarm_hosts()

    async def _probe(host: dict[str, Any]) -> HostHealth:
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
            return HostHealth(
                host_uuid=host["uuid"],
                name=host["name"],
                address=host["address"],
                reachable=True,
                detail=body,
            )
        except Exception as exc:
            log.warning("swarm.check unreachable host=%s err=%s", host["name"], exc)
            await repo.update_swarm_host(host["uuid"], {"status": "unreachable"})
            return HostHealth(
                host_uuid=host["uuid"],
                name=host["name"],
                address=host["address"],
                reachable=False,
                detail=str(exc),
            )

    results = await asyncio.gather(*(_probe(h) for h in hosts))
    return CheckResponse(results=list(results))
