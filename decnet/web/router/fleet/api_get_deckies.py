from typing import Any

from fastapi import APIRouter, Depends

from decnet.web.dependencies import require_viewer, repo

router = APIRouter()


@router.get("/deckies", tags=["Fleet Management"],
    responses={401: {"description": "Could not validate credentials"}, 422: {"description": "Validation error"}},)
async def get_deckies(user: dict = Depends(require_viewer)) -> list[dict[str, Any]]:
    return await repo.get_deckies()
