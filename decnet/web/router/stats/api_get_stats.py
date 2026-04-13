from typing import Any

from fastapi import APIRouter, Depends

from decnet.web.dependencies import get_current_user, repo
from decnet.web.db.models import StatsResponse

router = APIRouter()


@router.get("/stats", response_model=StatsResponse, tags=["Observability"],
    responses={401: {"description": "Could not validate credentials"}, 422: {"description": "Validation error"}},)
async def get_stats(current_user: str = Depends(get_current_user)) -> dict[str, Any]:
    return await repo.get_stats_summary()
