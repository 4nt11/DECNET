from fastapi import APIRouter, Depends, HTTPException

from decnet.mutator import mutate_decky
from decnet.web.dependencies import get_current_user

router = APIRouter()


@router.post("/deckies/{decky_name}/mutate", tags=["Fleet Management"])
async def api_mutate_decky(decky_name: str, current_user: str = Depends(get_current_user)) -> dict[str, str]:
    success = mutate_decky(decky_name)
    if success:
        return {"message": f"Successfully mutated {decky_name}"}
    raise HTTPException(status_code=404, detail=f"Decky {decky_name} not found or failed to mutate")
