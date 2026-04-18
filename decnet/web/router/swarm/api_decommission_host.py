"""DELETE /swarm/hosts/{uuid} — decommission a worker.

Removes the DeckyShard rows bound to the host (portable cascade — MySQL
and SQLite both honor it via the repo layer), deletes the SwarmHost row,
and best-effort-cleans the per-worker bundle directory on the master.
"""
from __future__ import annotations

import pathlib

from fastapi import APIRouter, Depends, HTTPException, status

from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo

router = APIRouter()


@router.delete(
    "/hosts/{uuid}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Swarm Hosts"],
)
async def api_decommission_host(
    uuid: str,
    repo: BaseRepository = Depends(get_repo),
) -> None:
    row = await repo.get_swarm_host_by_uuid(uuid)
    if row is None:
        raise HTTPException(status_code=404, detail="host not found")

    await repo.delete_decky_shards_for_host(uuid)
    await repo.delete_swarm_host(uuid)

    # Best-effort bundle cleanup; if the dir was moved manually, don't fail.
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
