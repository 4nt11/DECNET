from fastapi import APIRouter, Depends

from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.web.db.models import StartAllResponse, StartFailure
from decnet.web.dependencies import require_admin
from decnet.web.services import systemd_control
from decnet.web.worker_registry import KNOWN_WORKERS

log = get_logger("api")

router = APIRouter()


# Order matters — bus comes up first so subsequent workers have a place
# to publish their heartbeats; then the API, then the data-plane set.
# Anything unknown in KNOWN_WORKERS but not here gets appended at the
# end so new worker names still get started even if we forget to place
# them explicitly.
_PREFERRED_ORDER: tuple[str, ...] = (
    "bus",
    "api",
    "collector",
    "profiler",
    "sniffer",
    "prober",
    "mutator",
    "reconciler",
    "reuse-correlator",
    "attribution",
    "enrich",
    "clusterer",
    "campaign-clusterer",
    "webhook",
    "orchestrator",
)


def _ordered() -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for name in _PREFERRED_ORDER:
        if name in KNOWN_WORKERS and name not in seen:
            out.append(name)
            seen.add(name)
    for name in KNOWN_WORKERS:
        if name not in seen:
            out.append(name)
            seen.add(name)
    return out


@router.post(
    "/workers/start-all",
    response_model=StartAllResponse,
    tags=["Observability"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.start_all_workers")
async def start_all_workers(
    admin: dict = Depends(require_admin),
) -> StartAllResponse:
    """Best-effort: bring up every installed worker unit in order.

    Workers already ``active`` are counted in ``already_running`` and
    skipped.  Workers without a unit file (common on dev boxes) are
    silently skipped — the UI already renders them as not-installed.
    Returns 200 even on partial failure; the caller reads the three
    lists.  Started sequentially, not in parallel: systemd dependency
    ordering (bus → api → data-plane) matters.
    """
    installed = await systemd_control.list_installed()
    started: list[str] = []
    already_running: list[str] = []
    failed: list[StartFailure] = []

    for name in _ordered():
        if name not in installed:
            continue
        try:
            if await systemd_control.is_active(name):
                already_running.append(name)
                continue
            await systemd_control.start(name)
            started.append(name)
        except systemd_control.SystemctlError as exc:
            snippet = (exc.stderr.splitlines() or ["systemctl failed"])[0][:200]
            failed.append(StartFailure(name=name, reason=snippet))
            log.warning("start-all: %s failed: %s", name, snippet)

    log.info(
        "workers: start-all by=%s started=%d already=%d failed=%d",
        admin.get("username") or admin.get("sub") or "admin",
        len(started), len(already_running), len(failed),
    )
    return StartAllResponse(
        started=started,
        already_running=already_running,
        failed=failed,
    )
