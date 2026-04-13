from fastapi import APIRouter, Depends, HTTPException

from decnet.config import DecnetConfig
from decnet.web.dependencies import get_current_user, repo
from decnet.web.db.models import MutateIntervalRequest

router = APIRouter()

_UNIT_TO_MINUTES = {"m": 1, "d": 1440, "M": 43200, "y": 525600, "Y": 525600}


def _parse_duration(s: str) -> int:
    """Convert a duration string (e.g. '5d') to minutes."""
    value, unit = int(s[:-1]), s[-1]
    return value * _UNIT_TO_MINUTES[unit]


@router.put("/deckies/{decky_name}/mutate-interval", tags=["Fleet Management"],
    responses={
        400: {"description": "Bad Request (e.g. malformed JSON)"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "No active deployment or decky not found"},
        422: {"description": "Validation error"}
    },
)
async def api_update_mutate_interval(decky_name: str, req: MutateIntervalRequest, current_user: str = Depends(get_current_user)) -> dict[str, str]:
    state_dict = await repo.get_state("deployment")
    if not state_dict:
        raise HTTPException(status_code=404, detail="No active deployment")

    config = DecnetConfig(**state_dict["config"])
    compose_path = state_dict["compose_path"]

    decky = next((d for d in config.deckies if d.name == decky_name), None)
    if not decky:
        raise HTTPException(status_code=404, detail="Decky not found")

    decky.mutate_interval = _parse_duration(req.mutate_interval) if req.mutate_interval else None

    await repo.set_state("deployment", {"config": config.model_dump(), "compose_path": compose_path})
    return {"message": "Mutation interval updated"}
