"""GET /swarm/deckies — admin-gated list of decky shards across the fleet."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends

from decnet.web.db.models import DeckyShardView
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

router = APIRouter()


@router.get("/deckies", response_model=list[DeckyShardView], tags=["Swarm Management"])
async def list_deckies(
    host_uuid: Optional[str] = None,
    state: Optional[str] = None,
    admin: dict = Depends(require_admin),
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
            host_uuid=s["host_uuid"],
            host_name=host.get("name") or "<unknown>",
            host_address=host.get("address") or "",
            host_status=host.get("status") or "unknown",
            services=s.get("services") or [],
            state=s.get("state") or "pending",
            last_error=s.get("last_error"),
            compose_hash=s.get("compose_hash"),
            updated_at=s["updated_at"],
        ))
    return out
