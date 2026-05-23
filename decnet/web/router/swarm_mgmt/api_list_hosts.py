# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /swarm/hosts — admin-gated list of enrolled workers for the dashboard.

Fans out an ``AgentClient.health()`` probe to each host on every call and
updates ``status`` / ``last_heartbeat`` as a side effect. This mirrors how
``/swarm-updates/hosts`` probes the updater daemon — the SwarmHosts page
polls this endpoint, so probe-on-read is what drives heartbeat freshness
in the UI. No separate scheduler needed.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends

from decnet.logging import get_logger
from decnet.swarm.client import AgentClient
from decnet.web.db.models import SwarmHostView
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

log = get_logger("swarm_mgmt.list_hosts")

router = APIRouter()


async def _probe_and_update(
    host: dict[str, Any], repo: BaseRepository
) -> dict[str, Any]:
    """Best-effort mTLS probe. Skips hosts with no address yet (pending first
    connect-back) so we don't pollute the DB with 'unreachable' on fresh
    enrollments that haven't fetched the tarball."""
    if not host.get("address"):
        return host
    try:
        async with AgentClient(host=host) as agent:
            await agent.health()
        patch = {"status": "active", "last_heartbeat": datetime.now(timezone.utc)}
    except Exception as exc:  # noqa: BLE001
        log.debug("swarm/hosts probe unreachable host=%s err=%s", host.get("name"), exc)
        patch = {"status": "unreachable"}
    try:
        await repo.update_swarm_host(host["uuid"], patch)
    except Exception as exc:  # noqa: BLE001
        log.warning("swarm/hosts could not persist probe result host=%s err=%s", host.get("name"), exc)
        return host
    host.update(patch)
    return host


@router.get("/hosts", response_model=list[SwarmHostView], tags=["Swarm Management"])
async def list_hosts(
    host_status: Optional[str] = None,
    admin: dict = Depends(require_admin),
    repo: BaseRepository = Depends(get_repo),
) -> list[SwarmHostView]:
    rows = await repo.list_swarm_hosts(host_status)
    probed = await asyncio.gather(*(_probe_and_update(r, repo) for r in rows))
    return [SwarmHostView(**r) for r in probed]
