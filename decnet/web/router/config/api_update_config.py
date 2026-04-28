from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_admin, repo
from decnet.web.db.models import DeploymentLimitRequest, GlobalMutationIntervalRequest, MessageResponse

router = APIRouter()


@router.put(
    "/config/deployment-limit",
    tags=["Configuration"],
    response_model=MessageResponse,
    responses={
        400: {"description": "Bad Request (e.g. malformed JSON)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.update_deployment_limit")
async def api_update_deployment_limit(
    req: DeploymentLimitRequest,
    admin: dict = Depends(require_admin),
) -> dict[str, str]:
    await repo.set_state("config_limits", {"deployment_limit": req.deployment_limit})
    return {"message": "Deployment limit updated"}


@router.put(
    "/config/global-mutation-interval",
    tags=["Configuration"],
    response_model=MessageResponse,
    responses={
        400: {"description": "Bad Request (e.g. malformed JSON)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.update_global_mutation_interval")
async def api_update_global_mutation_interval(
    req: GlobalMutationIntervalRequest,
    admin: dict = Depends(require_admin),
) -> dict[str, str]:
    await repo.set_state(
        "config_globals",
        {"global_mutation_interval": req.global_mutation_interval},
    )
    return {"message": "Global mutation interval updated"}
