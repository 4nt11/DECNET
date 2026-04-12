from fastapi import APIRouter, Depends, HTTPException

from decnet.config import DecnetConfig
from decnet.web.dependencies import get_current_user, repo
from decnet.web.db.models import MutateIntervalRequest

router = APIRouter()


@router.put("/deckies/{decky_name}/mutate-interval", tags=["Fleet Management"],
    responses={
        400: {"description": "No active deployment found"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Decky not found"},
        422: {"description": "Validation error"}
    },
)
async def api_update_mutate_interval(decky_name: str, req: MutateIntervalRequest, current_user: str = Depends(get_current_user)) -> dict[str, str]:
    state_dict = await repo.get_state("deployment")
    if not state_dict:
        raise HTTPException(status_code=400, detail="No active deployment")

    config = DecnetConfig(**state_dict["config"])
    compose_path = state_dict["compose_path"]

    decky = next((d for d in config.deckies if d.name == decky_name), None)
    if not decky:
        raise HTTPException(status_code=404, detail="Decky not found")

    decky.mutate_interval = req.mutate_interval

    await repo.set_state("deployment", {"config": config.model_dump(), "compose_path": compose_path})
    return {"message": "Mutation interval updated"}
