"""DELETE /swarm/hosts/{uuid} — decommission a worker from the dashboard."""
from __future__ import annotations

import pathlib

from fastapi import APIRouter, Depends, HTTPException, status

from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

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
