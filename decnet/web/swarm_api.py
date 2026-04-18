"""DECNET SWARM Controller — master-side control plane.

Runs as an independent FastAPI/uvicorn process.  Isolated from
``decnet.web.api`` so controller failure cannot cascade to the main API,
ingester, or dashboard (mirrors the existing pattern used by
``decnet api`` with ``start_new_session=True``).

Responsibilities:
* host enrollment (issues CA-signed worker bundles);
* dispatching DecnetConfig shards to worker agents over mTLS;
* active health probes of enrolled workers.

The controller *reuses* the same ``get_repo`` dependency as the main API,
so SwarmHost / DeckyShard state is visible to both processes via the
shared DB.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import ORJSONResponse

from decnet.logging import get_logger
from decnet.swarm import pki
from decnet.swarm.client import ensure_master_identity
from decnet.web.dependencies import repo
from decnet.web.router.swarm import swarm_router

log = get_logger("swarm_api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    log.info("swarm-controller starting up")
    # Make sure the CA and master client cert exist before we accept any
    # request — enrollment needs them and AgentClient needs them.
    pki.ensure_ca()
    ensure_master_identity()
    await repo.initialize()
    log.info("swarm-controller ready")
    yield
    log.info("swarm-controller shutdown")


app: FastAPI = FastAPI(
    title="DECNET SWARM Controller",
    version="0.1.0",
    lifespan=lifespan,
    default_response_class=ORJSONResponse,
    # No interactive docs: the controller is an internal management plane,
    # not a public surface.  Enable explicitly in dev if needed.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.include_router(swarm_router)


@app.get("/health")
async def root_health() -> dict[str, str]:
    """Top-level liveness probe (no DB I/O)."""
    return {"status": "ok", "role": "swarm-controller"}
