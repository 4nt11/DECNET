# SPDX-License-Identifier: AGPL-3.0-or-later
import time

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import ORJSONResponse

from decnet.bus import topics as _topics
from decnet.bus.app import get_app_bus
from decnet.bus.publish import publish_safely
from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.web.db.models import WorkerControlResponse
from decnet.web.dependencies import require_admin
from decnet.web.worker_registry import KNOWN_WORKERS

log = get_logger("api")

router = APIRouter()


@router.post(
    "/workers/{name}/stop",
    tags=["Observability"],
    responses={
        202: {"model": WorkerControlResponse, "description": "Stop intent queued on bus"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Unknown worker"},
        503: {"description": "Bus unavailable"},
    },
)
@_traced("api.stop_worker")
async def stop_worker(
    name: str,
    admin: dict = Depends(require_admin),
) -> ORJSONResponse:
    """Publish a stop intent on ``system.<name>.control``.

    Fire-and-forget: the endpoint does not wait for the worker to
    actually exit — the caller observes the status row in the Workers
    panel flipping to ``stale`` as heartbeats stop.  Consistent with the
    rest of the bus contract (at-most-once, DB is source of truth for
    any persistent state; the bus is the notification layer).
    """
    if name not in KNOWN_WORKERS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown worker: {name!r}",
        )

    bus = await get_app_bus()
    if bus is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="bus unavailable",
        )
    topic = _topics.system_control(name)
    payload = {
        "action": _topics.WORKER_CONTROL_STOP,
        "requested_by": admin.get("username") or admin.get("sub") or "admin",
        "ts": time.time(),
    }
    await publish_safely(bus, topic, payload, event_type=_topics.SYSTEM_CONTROL)
    log.info(
        "workers: stop requested worker=%s by=%s",
        name, payload["requested_by"],
    )

    body = WorkerControlResponse(
        accepted=True,
        worker=name,
        action=_topics.WORKER_CONTROL_STOP,
    )
    return ORJSONResponse(
        content=body.model_dump(),
        status_code=status.HTTP_202_ACCEPTED,
    )
