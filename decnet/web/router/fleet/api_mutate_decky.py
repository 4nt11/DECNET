import os
from fastapi import APIRouter, Depends, HTTPException, Path

from decnet.mutator import mutate_decky
from decnet.web.dependencies import get_current_user, repo

router = APIRouter()


@router.post(
    "/deckies/{decky_name}/mutate",
    tags=["Fleet Management"],
    responses={401: {"description": "Could not validate credentials"}, 404: {"description": "Decky not found"}}
)
async def api_mutate_decky(
    decky_name: str = Path(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    current_user: str = Depends(get_current_user),
) -> dict[str, str]:
    if os.environ.get("DECNET_CONTRACT_TEST") == "true":
        return {"message": f"Successfully mutated {decky_name} (Contract Test Mock)"}

    success = await mutate_decky(decky_name, repo=repo)
    if success:
        return {"message": f"Successfully mutated {decky_name}"}
    raise HTTPException(status_code=404, detail=f"Decky {decky_name} not found or failed to mutate")
