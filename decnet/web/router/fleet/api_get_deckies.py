from typing import Any

from fastapi import APIRouter, Depends

from decnet.web.dependencies import get_current_user, repo

router = APIRouter()


@router.get("/deckies", tags=["Fleet Management"])
async def get_deckies(current_user: str = Depends(get_current_user)) -> list[dict[str, Any]]:
    return await repo.get_deckies()
