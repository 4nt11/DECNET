import time

from fastapi import APIRouter, Depends

from decnet.bus.app import get_app_bus
from decnet.telemetry import traced as _traced
from decnet.web.db.models import WorkersResponse
from decnet.web.dependencies import require_viewer
from decnet.web.services import systemd_control
from decnet.web.worker_registry import get_registry

router = APIRouter()


@router.get(
    "/workers",
    response_model=WorkersResponse,
    tags=["Observability"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.list_workers")
async def list_workers(user: dict = Depends(require_viewer)) -> WorkersResponse:
    workers = get_registry().snapshot()
    bus = await get_app_bus()
    installed = await systemd_control.list_installed()
    for w in workers:
        w.installed = w.name in installed
    return WorkersResponse(
        workers=workers,
        generated_at=time.time(),
        bus_connected=bus is not None,
    )
