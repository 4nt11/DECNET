from fastapi import APIRouter, Depends

from decnet.env import DECNET_DEVELOPER
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import UserResponse

router = APIRouter()

_DEFAULT_DEPLOYMENT_LIMIT = 10
_DEFAULT_MUTATION_INTERVAL = "30m"


@router.get(
    "/config",
    tags=["Configuration"],
    responses={
        401: {"description": "Could not validate credentials"},
    },
)
async def api_get_config(user: dict = Depends(require_viewer)) -> dict:
    limits_state = await repo.get_state("config_limits")
    globals_state = await repo.get_state("config_globals")

    deployment_limit = (
        limits_state.get("deployment_limit", _DEFAULT_DEPLOYMENT_LIMIT)
        if limits_state
        else _DEFAULT_DEPLOYMENT_LIMIT
    )
    global_mutation_interval = (
        globals_state.get("global_mutation_interval", _DEFAULT_MUTATION_INTERVAL)
        if globals_state
        else _DEFAULT_MUTATION_INTERVAL
    )

    base = {
        "role": user["role"],
        "deployment_limit": deployment_limit,
        "global_mutation_interval": global_mutation_interval,
    }

    if user["role"] == "admin":
        all_users = await repo.list_users()
        base["users"] = [
            UserResponse(
                uuid=u["uuid"],
                username=u["username"],
                role=u["role"],
                must_change_password=u["must_change_password"],
            ).model_dump()
            for u in all_users
        ]
        if DECNET_DEVELOPER:
            base["developer_mode"] = True

    return base
