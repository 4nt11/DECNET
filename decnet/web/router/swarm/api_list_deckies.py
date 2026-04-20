"""GET /swarm/deckies — list decky shards with their worker host's identity.

The DeckyShard table maps decky_name → host_uuid; users want to see which
deckies are running and *where*, so we enrich each shard with the owning
host's name/address/status from SwarmHost rather than making callers do
the join themselves.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends

from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo
from decnet.web.db.models import DeckyShardView

router = APIRouter()


@router.get("/deckies", response_model=list[DeckyShardView], tags=["Swarm Deckies"])
async def api_list_deckies(
    host_uuid: Optional[str] = None,
    state: Optional[str] = None,
    repo: BaseRepository = Depends(get_repo),
) -> list[DeckyShardView]:
    shards = await repo.list_decky_shards(host_uuid)
    hosts = {h["uuid"]: h for h in await repo.list_swarm_hosts()}

    out: list[DeckyShardView] = []
    for s in shards:
        if state and s.get("state") != state:
            continue
        host = hosts.get(s["host_uuid"], {})
        out.append(DeckyShardView(
            decky_name=s["decky_name"],
            decky_ip=s.get("decky_ip"),
            host_uuid=s["host_uuid"],
            host_name=host.get("name") or "<unknown>",
            host_address=host.get("address") or "",
            host_status=host.get("status") or "unknown",
            services=s.get("services") or [],
            state=s.get("state") or "pending",
            last_error=s.get("last_error"),
            compose_hash=s.get("compose_hash"),
            updated_at=s["updated_at"],
            hostname=s.get("hostname"),
            distro=s.get("distro"),
            archetype=s.get("archetype"),
            service_config=s.get("service_config") or {},
            mutate_interval=s.get("mutate_interval"),
            last_mutated=s.get("last_mutated") or 0.0,
            last_seen=s.get("last_seen"),
        ))
    return out
