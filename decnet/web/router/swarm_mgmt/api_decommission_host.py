"""DELETE /swarm/hosts/{uuid} — decommission a worker from the dashboard.

Also instructs the worker agent to stop all DECNET services and delete
its install footprint (keeping logs). Agent self-destruct failure does
not block decommission — the master-side cleanup always runs so a dead
worker can still be removed from the dashboard.
"""
from __future__ import annotations

import pathlib

from fastapi import APIRouter, Depends, HTTPException, status

from decnet.logging import get_logger
from decnet.swarm.client import AgentClient
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

log = get_logger("swarm.decommission")
router = APIRouter()


@router.delete(
    "/hosts/{uuid}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Swarm Management"],
)
async def decommission_host(
    uuid: str,
    admin: dict = Depends(require_admin),
    repo: BaseRepository = Depends(get_repo),
) -> None:
    row = await repo.get_swarm_host_by_uuid(uuid)
    if row is None:
        raise HTTPException(status_code=404, detail="host not found")

    # Ask the worker to wipe its own install (keeps logs). The agent
    # schedules the reaper as a detached process and returns immediately,
    # so this call is fast when the worker is reachable. A dead worker
    # shouldn't block the operator from cleaning up the dashboard entry,
    # hence best-effort with a log and continue.
    try:
        async with AgentClient(host=row) as agent:
            await agent.self_destruct()
    except Exception:
        log.exception(
            "decommission: self-destruct dispatch failed host=%s — "
            "proceeding with master-side cleanup anyway",
            row.get("name"),
        )

    await repo.delete_decky_shards_for_host(uuid)
    await repo.delete_swarm_host(uuid)

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
