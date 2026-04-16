from typing import Any

from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import StatsResponse

router = APIRouter()


@router.get("/stats", response_model=StatsResponse, tags=["Observability"],
    responses={401: {"description": "Could not validate credentials"}, 422: {"description": "Validation error"}},)
@_traced("api.get_stats")
async def get_stats(user: dict = Depends(require_viewer)) -> dict[str, Any]:
    return await repo.get_stats_summary()
