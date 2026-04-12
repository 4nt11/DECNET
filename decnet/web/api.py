import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from decnet.env import DECNET_CORS_ORIGINS, DECNET_DEVELOPER, DECNET_INGEST_LOG_FILE
from decnet.web.dependencies import repo
from decnet.collector import log_collector_worker
from decnet.web.ingester import log_ingestion_worker
from decnet.web.router import api_router

log = logging.getLogger(__name__)
ingestion_task: Optional[asyncio.Task[Any]] = None
collector_task: Optional[asyncio.Task[Any]] = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global ingestion_task, collector_task

    for attempt in range(1, 6):
        try:
            await repo.initialize()
            break
        except Exception as exc:
            log.warning("DB init attempt %d/5 failed: %s", attempt, exc)
            if attempt == 5:
                log.error("DB failed to initialize after 5 attempts — startup may be degraded")
            await asyncio.sleep(0.5)

    # Start background tasks only if not in contract test mode
    if os.environ.get("DECNET_CONTRACT_TEST") != "true":
        # Start background ingestion task
        if ingestion_task is None or ingestion_task.done():
            ingestion_task = asyncio.create_task(log_ingestion_worker(repo))

        # Start Docker log collector (writes to log file; ingester reads from it)
        _log_file = os.environ.get("DECNET_INGEST_LOG_FILE", DECNET_INGEST_LOG_FILE)
        if _log_file and (collector_task is None or collector_task.done()):
            collector_task = asyncio.create_task(log_collector_worker(_log_file))
        elif not _log_file:
            log.warning("DECNET_INGEST_LOG_FILE not set — Docker log collection disabled.")
    else:
        log.info("Contract Test Mode: skipping background worker startup")

    yield

    # Shutdown background tasks
    for task in (ingestion_task, collector_task):
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                log.warning("Task shutdown error: %s", exc)


app: FastAPI = FastAPI(
    title="DECNET Web Dashboard API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if DECNET_DEVELOPER else None,
    redoc_url="/redoc" if DECNET_DEVELOPER else None,
    openapi_url="/openapi.json" if DECNET_DEVELOPER else None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=DECNET_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Last-Event-ID"],
)

# Include the modular API router
app.include_router(api_router, prefix="/api/v1")
