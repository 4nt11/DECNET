import time
from typing import Any, Optional

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import HealthResponse, ComponentHealth

router = APIRouter()

_OPTIONAL_SERVICES = {"sniffer_worker"}

# Cache Docker client and health result to avoid hammering the Docker socket
_docker_client: Optional[Any] = None
_docker_healthy: bool = False
_docker_detail: str = ""
_docker_last_check: float = 0.0
_DOCKER_CHECK_INTERVAL = 5.0  # seconds between actual Docker pings


def _reset_docker_cache() -> None:
    """Reset cached Docker state — used by tests."""
    global _docker_client, _docker_healthy, _docker_detail, _docker_last_check
    _docker_client = None
    _docker_healthy = False
    _docker_detail = ""
    _docker_last_check = 0.0


@router.get(
    "/health",
    response_model=HealthResponse,
    tags=["Observability"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        503: {"model": HealthResponse, "description": "System unhealthy"},
    },
)
@_traced("api.get_health")
async def get_health(user: dict = Depends(require_viewer)) -> Any:
    components: dict[str, ComponentHealth] = {}

    # 1. Database
    try:
        await repo.get_total_logs()
        components["database"] = ComponentHealth(status="ok")
    except Exception as exc:
        components["database"] = ComponentHealth(status="failing", detail=str(exc))

    # 2. Background workers
    from decnet.web.api import get_background_tasks
    for name, task in get_background_tasks().items():
        if task is None:
            components[name] = ComponentHealth(status="failing", detail="not started")
        elif task.done():
            if task.cancelled():
                detail = "cancelled"
            else:
                exc = task.exception()
                detail = f"exited: {exc}" if exc else "exited unexpectedly"
            components[name] = ComponentHealth(status="failing", detail=detail)
        else:
            components[name] = ComponentHealth(status="ok")

    # 3. Docker daemon (cached — avoids creating a new client per request)
    global _docker_client, _docker_healthy, _docker_detail, _docker_last_check
    now = time.monotonic()
    if now - _docker_last_check > _DOCKER_CHECK_INTERVAL:
        try:
            import docker

            if _docker_client is None:
                _docker_client = docker.from_env()
            _docker_client.ping()
            _docker_healthy = True
            _docker_detail = ""
        except Exception as exc:
            _docker_client = None
            _docker_healthy = False
            _docker_detail = str(exc)
        _docker_last_check = now

    if _docker_healthy:
        components["docker"] = ComponentHealth(status="ok")
    else:
        components["docker"] = ComponentHealth(status="failing", detail=_docker_detail)

    # Compute overall status
    required_failing = any(
        c.status == "failing"
        for name, c in components.items()
        if name not in _OPTIONAL_SERVICES
    )
    optional_failing = any(
        c.status == "failing"
        for name, c in components.items()
        if name in _OPTIONAL_SERVICES
    )

    if required_failing:
        overall = "unhealthy"
    elif optional_failing:
        overall = "degraded"
    else:
        overall = "healthy"

    result = HealthResponse(status=overall, components=components)
    status_code = 503 if overall == "unhealthy" else 200
    return JSONResponse(content=result.model_dump(), status_code=status_code)
