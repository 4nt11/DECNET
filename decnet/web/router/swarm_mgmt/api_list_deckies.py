# SPDX-License-Identifier: AGPL-3.0-or-later
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

    # Pre-heartbeat fallback — older rows without decky_config can still
    # surface their IP from the master's deploy state snapshot.
    deploy_state = await repo.get_state("deployment") or {}
    cfg_deckies = (deploy_state.get("config") or {}).get("deckies") or []
    ip_by_name: dict[str, str] = {
        d.get("name"): d.get("ip") for d in cfg_deckies if d.get("name")
    }

    out: list[DeckyShardView] = []
    for s in shards:
        if state and s.get("state") != state:
            continue
        host = hosts.get(s["host_uuid"], {})
        out.append(DeckyShardView(
            decky_name=s["decky_name"],
            decky_ip=s.get("decky_ip") or ip_by_name.get(s["decky_name"]),
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
