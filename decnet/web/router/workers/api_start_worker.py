# SPDX-License-Identifier: AGPL-3.0-or-later
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import ORJSONResponse

from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.web.db.models import WorkerControlResponse
from decnet.web.dependencies import require_admin
from decnet.web.services import systemd_control
from decnet.web.worker_registry import KNOWN_WORKERS

log = get_logger("api")

router = APIRouter()


@router.post(
    "/workers/{name}/start",
    tags=["Observability"],
    responses={
        202: {"model": WorkerControlResponse, "description": "Start issued via systemd"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Unknown worker"},
        502: {"description": "systemctl returned non-zero"},
        503: {"description": "Unit file not installed on this host"},
    },
)
@_traced("api.start_worker")
async def start_worker(
    name: str,
    admin: dict = Depends(require_admin),
) -> ORJSONResponse:
    """Start ``decnet-<name>.service`` via systemd.

    Unlike STOP (which is bus-based — the worker signals itself), START
    has to come from *outside* the worker since a stopped worker has no
    subscriber.  The API shells out to ``systemctl`` via a scoped polkit
    rule.  Returns 202 on acceptance; the UI then waits for the next
    REFRESH to see the heartbeat flip the row to OK.
    """
    if name not in KNOWN_WORKERS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown worker: {name!r}",
        )

    installed = await systemd_control.list_installed()
    if name not in installed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"unit file not installed: decnet-{name}.service",
        )

    try:
        await systemd_control.start(name)
    except systemd_control.SystemctlError as exc:
        log.exception("systemctl start %s failed: %s", name, exc.stderr)
        snippet = exc.stderr.splitlines()[0] if exc.stderr else "systemctl failed"
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=snippet[:200],
        ) from exc

    log.info(
        "workers: start requested worker=%s by=%s",
        name, admin.get("username") or admin.get("sub") or "admin",
    )
    body = WorkerControlResponse(accepted=True, worker=name, action="start")
    return ORJSONResponse(
        content=body.model_dump(),
        status_code=status.HTTP_202_ACCEPTED,
    )
