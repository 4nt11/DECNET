from fastapi import APIRouter, Depends, HTTPException

from decnet.env import DECNET_DEVELOPER
from decnet.web.dependencies import require_admin, repo

router = APIRouter()


@router.delete(
    "/config/reinit",
    tags=["Configuration"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required or developer mode not enabled"},
    },
)
async def api_reinit(admin: dict = Depends(require_admin)) -> dict:
    if not DECNET_DEVELOPER:
        raise HTTPException(status_code=403, detail="Developer mode is not enabled")

    counts = await repo.purge_logs_and_bounties()
    return {
        "message": "Data purged",
        "deleted": counts,
    }
