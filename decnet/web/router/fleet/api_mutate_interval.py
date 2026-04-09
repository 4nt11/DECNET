from fastapi import APIRouter, Depends, HTTPException

from decnet.config import load_state, save_state
from decnet.web.dependencies import get_current_user
from decnet.web.models import MutateIntervalRequest

router = APIRouter()


@router.put("/deckies/{decky_name}/mutate-interval", tags=["Fleet Management"])
async def api_update_mutate_interval(decky_name: str, req: MutateIntervalRequest, current_user: str = Depends(get_current_user)) -> dict[str, str]:
    state = load_state()
    if not state:
        raise HTTPException(status_code=500, detail="No active deployment")
    config, compose_path = state
    decky = next((d for d in config.deckies if d.name == decky_name), None)
    if not decky:
        raise HTTPException(status_code=404, detail="Decky not found")
    decky.mutate_interval = req.mutate_interval
    save_state(config, compose_path)
    return {"message": "Mutation interval updated"}
