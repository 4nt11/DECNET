import os
from fastapi import APIRouter, Depends, HTTPException, Path

from decnet.telemetry import traced as _traced
from decnet.mutator import mutate_decky
from decnet.web.dependencies import require_admin, repo

router = APIRouter()


@router.post(
    "/deckies/{decky_name}/mutate",
    tags=["Fleet Management"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Decky not found"},
        422: {"description": "Path parameter validation error (decky_name must match ^[a-z0-9\\-]{1,64}$)"},
    }
)
@_traced("api.mutate_decky")
async def api_mutate_decky(
    decky_name: str = Path(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    admin: dict = Depends(require_admin),
) -> dict[str, str]:
    if os.environ.get("DECNET_CONTRACT_TEST") == "true":
        return {"message": f"Successfully mutated {decky_name} (Contract Test Mock)"}

    success = await mutate_decky(decky_name, repo=repo)
    if success:
        return {"message": f"Successfully mutated {decky_name}"}
    raise HTTPException(status_code=404, detail=f"Decky {decky_name} not found or failed to mutate")
