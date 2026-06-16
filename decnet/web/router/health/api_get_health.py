# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends
from fastapi.responses import ORJSONResponse

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import HealthResponse, ComponentHealth

router = APIRouter()

_CRITICAL_SERVICES = {"database", "docker", "ingestion_worker"}

# Cache Docker client and health result to avoid hammering the Docker socket
_docker_client: Optional[Any] = None
_docker_healthy: bool = False
_docker_detail: str = ""
_docker_last_check: float = 0.0
_DOCKER_CHECK_INTERVAL = 5.0  # seconds between actual Docker pings

# Cache DB liveness result — under load, every request was hitting
# repo.get_total_logs() and filling the aiosqlite queue.
_db_component: Optional[ComponentHealth] = None
_db_last_check: float = 0.0
# Lazy-init — an asyncio.Lock bound to a dead event loop deadlocks any
# later test running under a fresh loop.  Create on first use.
_db_lock: Optional[asyncio.Lock] = None
_DB_CHECK_INTERVAL = 1.0  # seconds


def _reset_docker_cache() -> None:
    """Reset cached Docker state — used by tests."""
    global _docker_client, _docker_healthy, _docker_detail, _docker_last_check
    _docker_client = None
    _docker_healthy = False
    _docker_detail = ""
    _docker_last_check = 0.0


def _reset_db_cache() -> None:
    """Reset cached DB liveness — used by tests."""
    global _db_component, _db_last_check, _db_lock
    _db_component = None
    _db_last_check = 0.0
    _db_lock = None


async def _check_database_cached() -> ComponentHealth:
    global _db_component, _db_last_check, _db_lock
    now = time.monotonic()
    if _db_component is not None and now - _db_last_check < _DB_CHECK_INTERVAL:
        return _db_component
    if _db_lock is None:
        _db_lock = asyncio.Lock()
    async with _db_lock:
        now = time.monotonic()
        if _db_component is not None and now - _db_last_check < _DB_CHECK_INTERVAL:
            return _db_component
        try:
            await repo.get_total_logs()
            _db_component = ComponentHealth(status="ok")
        except Exception:
            import logging as _logging
            _logging.getLogger("api.get_health").exception("database liveness check failed")
            _db_component = ComponentHealth(status="failing", detail="database unavailable")
        _db_last_check = time.monotonic()
        return _db_component


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

    # 1. Database (cached — avoids a DB round-trip per request)
    components["database"] = await _check_database_cached()

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
                detail = "exited unexpectedly" if not exc else "exited with error"
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
                _docker_client = await asyncio.to_thread(docker.from_env)
            await asyncio.to_thread(_docker_client.ping)  # type: ignore[union-attr]
            _docker_healthy = True
            _docker_detail = ""
        except Exception:
            import logging as _logging
            _logging.getLogger("api.get_health").exception("docker daemon ping failed")
            _docker_client = None
            _docker_healthy = False
            _docker_detail = "docker daemon unavailable"
        _docker_last_check = now

    if _docker_healthy:
        components["docker"] = ComponentHealth(status="ok")
    else:
        components["docker"] = ComponentHealth(status="failing", detail=_docker_detail)

    # Overall status tiers:
    #   healthy    — every component ok
    #   degraded   — only non-critical components failing (service usable,
    #                falls back to cache or skips non-essential work)
    #   unhealthy  — a critical component (db, docker, ingestion) failing;
    #                survival depends on caches
    critical_failing = any(
        c.status == "failing"
        for name, c in components.items()
        if name in _CRITICAL_SERVICES
    )
    noncritical_failing = any(
        c.status == "failing"
        for name, c in components.items()
        if name not in _CRITICAL_SERVICES
    )

    if critical_failing:
        overall = "unhealthy"
    elif noncritical_failing:
        overall = "degraded"
    else:
        overall = "healthy"

    result = HealthResponse(status=overall, components=components)
    status_code = 503 if overall == "unhealthy" else 200
    return ORJSONResponse(content=result.model_dump(), status_code=status_code)
