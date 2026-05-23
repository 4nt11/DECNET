# SPDX-License-Identifier: AGPL-3.0-or-later
from fastapi import APIRouter, Depends, HTTPException

from decnet.env import DECNET_DEVELOPER
from decnet.telemetry import traced as _traced
from decnet.web.db.models import PurgeResponse
from decnet.web.dependencies import require_admin, repo

router = APIRouter()


@router.delete(
    "/config/reinit",
    tags=["Configuration"],
    response_model=PurgeResponse,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required or developer mode not enabled"},
    },
)
@_traced("api.reinit")
async def api_reinit(admin: dict = Depends(require_admin)) -> dict:
    if not DECNET_DEVELOPER:
        raise HTTPException(status_code=403, detail="Developer mode is not enabled")

    counts = await repo.purge_logs_and_bounties()
    return {
        "message": "Data purged",
        "deleted": counts,
    }
