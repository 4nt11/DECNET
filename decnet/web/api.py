import asyncio
import os
import traceback
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Optional

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import ORJSONResponse
from pydantic import ValidationError
from fastapi.middleware.cors import CORSMiddleware

from decnet.env import (
    DECNET_CORS_ORIGINS,
    DECNET_DEVELOPER,
    DECNET_EMBED_COLLECTOR,
    DECNET_EMBED_PROFILER,
    DECNET_EMBED_SNIFFER,
    DECNET_INGEST_LOG_FILE,
    DECNET_PROFILE_DIR,
    DECNET_PROFILE_REQUESTS,
)
from decnet.logging import get_logger
from decnet.web.dependencies import repo
from decnet.collector import log_collector_worker
from decnet.web.ingester import log_ingestion_worker
from decnet.profiler import attacker_profile_worker
from decnet.web.limiter import limiter
from decnet.web.router import api_router
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

log = get_logger("api")
ingestion_task: Optional[asyncio.Task[Any]] = None
collector_task: Optional[asyncio.Task[Any]] = None
attacker_task: Optional[asyncio.Task[Any]] = None
sniffer_task: Optional[asyncio.Task[Any]] = None
heartbeat_task: Optional[asyncio.Task[Any]] = None


def get_background_tasks() -> dict[str, Optional[asyncio.Task[Any]]]:
    """Expose background task handles for the health endpoint."""
    return {
        "ingestion_worker": ingestion_task,
        "collector_worker": collector_task,
        "attacker_worker": attacker_task,
        "sniffer_worker": sniffer_task,
    }


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global ingestion_task, collector_task, attacker_task, sniffer_task
    global heartbeat_task

    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < 4096:
        log.warning(
            "Low open-file limit detected (ulimit -n = %d). "
            "High-traffic deployments may hit 'Too many open files' errors. "
            "Raise it with: ulimit -n 65536 (session) or LimitNOFILE=65536 (systemd)",
            soft,
        )

    log.info("API startup initialising database")
    for attempt in range(1, 6):
        try:
            await repo.initialize()
            log.debug("API startup DB initialised attempt=%d", attempt)
            break
        except Exception as exc:
            log.warning("DB init attempt %d/5 failed: %s", attempt, exc)
            if attempt == 5:
                log.error("DB failed to initialize after 5 attempts — startup may be degraded")
            await asyncio.sleep(0.5)

    # Conditionally enable OpenTelemetry tracing
    from decnet.telemetry import setup_tracing
    setup_tracing(app)

    # Start background tasks only if not in contract test mode
    if os.environ.get("DECNET_CONTRACT_TEST") != "true":
        # Start background ingestion task
        if ingestion_task is None or ingestion_task.done():
            ingestion_task = asyncio.create_task(log_ingestion_worker(repo))
            log.debug("API startup ingest worker started")

        # Start Docker log collector (writes to log file; ingester reads from it).
        # Gated on DECNET_EMBED_COLLECTOR: when `decnet-collector.service` (or
        # any other standalone collector) is running, embedding a second tailer
        # here writes every container line twice — the ingester then inserts
        # the same event into the DB twice, which surfaces as duplicate rows
        # on the dashboard.
        _log_file = os.environ.get("DECNET_INGEST_LOG_FILE", DECNET_INGEST_LOG_FILE)
        if DECNET_EMBED_COLLECTOR:
            if _log_file and (collector_task is None or collector_task.done()):
                collector_task = asyncio.create_task(log_collector_worker(_log_file))
                log.info(
                    "API startup: embedded collector started "
                    "(DECNET_EMBED_COLLECTOR=true) log_file=%s",
                    _log_file,
                )
            elif not _log_file:
                log.warning("DECNET_INGEST_LOG_FILE not set — embedded collector disabled.")
        else:
            log.debug("API startup: collector not embedded — expecting standalone daemon")

        # Start attacker profile rebuild worker only when explicitly requested.
        # Default is OFF because `decnet deploy` always starts a standalone
        # `decnet profiler --daemon` process.  Running both against the same
        # DB cursor causes events to be skipped or double-processed.
        if DECNET_EMBED_PROFILER:
            if attacker_task is None or attacker_task.done():
                attacker_task = asyncio.create_task(attacker_profile_worker(repo))
                log.info("API startup: embedded profiler started (DECNET_EMBED_PROFILER=true)")
        else:
            log.debug("API startup: profiler not embedded — expecting standalone daemon")

        # Start fleet-wide MACVLAN sniffer only when explicitly requested.
        # Default is OFF because `decnet deploy` always starts a standalone
        # `decnet sniffer --daemon` process. Running both against the same
        # interface produces duplicated events and wastes CPU.
        if DECNET_EMBED_SNIFFER:
            try:
                from decnet.sniffer import sniffer_worker
                if sniffer_task is None or sniffer_task.done():
                    sniffer_task = asyncio.create_task(sniffer_worker(_log_file))
                    log.info("API startup: embedded sniffer started (DECNET_EMBED_SNIFFER=true)")
            except Exception as exc:
                log.warning("Sniffer worker failed to start — API continues without sniffing: %s", exc)
        else:
            log.debug("API startup: sniffer not embedded — expecting standalone daemon")
    else:
        log.info("Contract Test Mode: skipping background worker startup")

    # Worker registry + API self-heartbeat — always on, even under
    # contract-test mode, so the Workers panel can render the process
    # without the dev needing to run a full stack.  A missing bus turns
    # both into no-ops inside the helpers.
    try:
        from decnet.bus.app import get_app_bus
        from decnet.bus.publish import run_health_heartbeat
        from decnet.web.worker_registry import get_registry

        _bus = await get_app_bus()
        await get_registry().start(_bus)
        if heartbeat_task is None or heartbeat_task.done():
            heartbeat_task = asyncio.create_task(
                run_health_heartbeat(_bus, "api"),
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("worker registry bootstrap failed: %s", exc)

    yield

    log.info("API shutdown cancelling background tasks")
    try:
        from decnet.web.worker_registry import get_registry
        await get_registry().stop()
    except Exception as exc:  # noqa: BLE001
        log.warning("worker registry stop raised: %s", exc)
    for task in (ingestion_task, collector_task, attacker_task, sniffer_task, heartbeat_task):
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                log.warning("Task shutdown error: %s", exc)
    from decnet.bus.app import close_app_bus
    await close_app_bus()
    from decnet.telemetry import shutdown_tracing
    shutdown_tracing()
    log.info("API shutdown complete")


app: FastAPI = FastAPI(
    title="DECNET Web Dashboard API",
    version="1.0.0",
    lifespan=lifespan,
    default_response_class=ORJSONResponse,
    docs_url="/docs" if DECNET_DEVELOPER else None,
    redoc_url="/redoc" if DECNET_DEVELOPER else None,
    openapi_url="/openapi.json" if DECNET_DEVELOPER else None
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=DECNET_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Last-Event-ID"],
)

if DECNET_PROFILE_REQUESTS:
    import time
    from pathlib import Path
    from pyinstrument import Profiler
    from starlette.middleware.base import BaseHTTPMiddleware

    _profile_dir = Path(DECNET_PROFILE_DIR)
    _profile_dir.mkdir(parents=True, exist_ok=True)

    class PyinstrumentMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            profiler = Profiler(async_mode="enabled")
            profiler.start()
            try:
                response = await call_next(request)
            finally:
                profiler.stop()
            slug = request.url.path.strip("/").replace("/", "_") or "root"
            out = _profile_dir / f"{int(time.time() * 1000)}-{request.method}-{slug}.html"
            out.write_text(profiler.output_html())
            return response

    app.add_middleware(PyinstrumentMiddleware)
    log.info("Pyinstrument middleware mounted — flamegraphs -> %s", _profile_dir)

# Include the modular API router
app.include_router(api_router, prefix="/api/v1")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> ORJSONResponse:
    """
    Handle validation errors with targeted status codes to satisfy contract tests.
    Tiered Prioritization:
    1. 400 Bad Request: For structural schema violations (extra fields, wrong types, missing fields).
       This satisfies Schemathesis 'Negative Data' checks.
    2. 409 Conflict: For semantic/structural INI content violations in valid strings.
       This satisfies Schemathesis 'Positive Data' checks.
    3. 422 Unprocessable: Default for other validation edge cases.
    """
    errors = exc.errors()

    # 1. Prioritize Structural Format Violations (Negative Data)
    # This catches: sending an object instead of a string, extra unknown properties, or empty-string length violations.
    is_structural_violation = any(
        err.get("type") in ("type_error", "extra_forbidden", "missing", "string_too_short", "string_type") or
        "must be a string" in err.get("msg", "")  # Catch our validator's type check
        for err in errors
    )
    if is_structural_violation:
        return ORJSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Bad Request: Schema structural violation (wrong type, extra fields, or invalid length)."},
        )

    # 2. Targeted INI Error Rejections
    # We distinguishes between different failure modes for precise contract compliance.

    # Empty INI content (Valid string but semantically empty)
    is_ini_empty = any("INI content is empty" in err.get("msg", "") for err in errors)
    if is_ini_empty:
        return ORJSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": "Configuration conflict: INI content is empty."},
        )

    # Invalid characters/syntax (Valid-length string but invalid INI syntax)
    # Mapping to 409 for Positive Data compliance.
    is_invalid_characters = any("Invalid INI format" in err.get("msg", "") for err in errors)
    if is_invalid_characters:
        return ORJSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": "Configuration conflict: INI syntax or characters are invalid."},
        )

    # Logical invalidity (Valid string, valid syntax, but missing required DECNET logic like sections)
    is_ini_invalid_logic = any("at least one section" in err.get("msg", "") for err in errors)
    if is_ini_invalid_logic:
        return ORJSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": "Invalid INI config structure: No decky sections found."},
        )

    # Developer Mode fallback
    if DECNET_DEVELOPER:
        from fastapi.exception_handlers import request_validation_exception_handler
        return await request_validation_exception_handler(request, exc)

    # Production/Strict mode fallback: Sanitize remaining 422s
    message = "Invalid request parameters"
    if "/deckies/deploy" in request.url.path:
        message = "Invalid INI config"

    return ORJSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": message},
    )

@app.exception_handler(ValidationError)
async def pydantic_validation_exception_handler(request: Request, exc: ValidationError) -> ORJSONResponse:
    """
    Handle Pydantic errors that occur during manual model instantiation (e.g. state hydration).
    Prevents 500 errors when the database contains inconsistent or outdated schema data.
    """
    log.error("Internal Pydantic validation error: %s", exc)
    return ORJSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Internal data consistency error",
            "type": "internal_validation_error"
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> ORJSONResponse:
    """Catch-all for uncaught exceptions in route handlers and dependencies.

    Prod: opaque 500 with an ``error_id``; full traceback goes ONLY to server
    logs. Dev (``DECNET_DEVELOPER=True``): same response plus ``exception_type``
    and ``traceback`` fields so failures are debuggable without tailing logs.

    The ``error_id`` lets operators correlate a user's 500 report with the full
    traceback in server logs (``grep <error_id> /var/log/decnet.log``).

    FastAPI's own ``HTTPException`` routing still takes precedence — this
    handler only fires on genuinely-uncaught exceptions.
    """
    error_id = uuid.uuid4().hex
    log.exception(
        "unhandled exception on %s %s [error_id=%s]",
        request.method, request.url.path, error_id,
    )
    body: dict[str, Any] = {"detail": "Internal Server Error", "error_id": error_id}
    if DECNET_DEVELOPER:
        body["exception_type"] = type(exc).__name__
        body["traceback"] = traceback.format_exc()
    return ORJSONResponse(status_code=500, content=body)
