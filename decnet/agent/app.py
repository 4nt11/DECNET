"""Worker-side FastAPI app.

Protected by mTLS at the ASGI/uvicorn transport layer: uvicorn is started
with ``--ssl-ca-certs`` + ``--ssl-cert-reqs 2`` (CERT_REQUIRED), so any
client that cannot prove a cert signed by the DECNET CA is rejected before
reaching a handler.  Once past the TLS handshake, all peers are trusted
equally (the only entity holding a CA-signed cert is the master
controller).

Endpoints mirror the existing unihost CLI verbs:

* ``POST /deploy``   — body: serialized ``DecnetConfig``
* ``POST /teardown`` — body: optional ``{"decky_id": "..."}``
* ``POST /mutate``   — body: ``{"decky_id": "...", "services": [...]}``
* ``GET  /status``   — deployment snapshot
* ``GET  /health``   — liveness probe, does NOT require mTLS? No — mTLS
  still required; master pings it with its cert.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from decnet.agent import executor as _exec
from decnet.agent import heartbeat as _heartbeat
from decnet.config import DecnetConfig
from decnet.logging import get_logger

log = get_logger("agent.app")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Best-effort: if identity/bundle plumbing isn't configured (e.g. dev
    # runs or non-enrolled hosts), heartbeat.start() is a silent no-op.
    _heartbeat.start()
    try:
        yield
    finally:
        await _heartbeat.stop()


app = FastAPI(
    title="DECNET SWARM Agent",
    version="0.1.0",
    docs_url=None,    # no interactive docs on worker — narrow attack surface
    redoc_url=None,
    openapi_url=None,
    lifespan=_lifespan,
)


# ------------------------------------------------------------------ schemas

class DeployRequest(BaseModel):
    config: DecnetConfig = Field(..., description="Full DecnetConfig to materialise on this worker")
    dry_run: bool = False
    no_cache: bool = False


class TeardownRequest(BaseModel):
    decky_id: Optional[str] = None


class MutateRequest(BaseModel):
    decky_id: str
    services: list[str]


# ------------------------------------------------------------------ routes

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/status")
async def status() -> dict:
    return await _exec.status()


@app.post("/deploy")
async def deploy(req: DeployRequest) -> dict:
    try:
        await _exec.deploy(req.config, dry_run=req.dry_run, no_cache=req.no_cache)
    except Exception as exc:
        log.exception("agent.deploy failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"status": "deployed", "deckies": len(req.config.deckies)}


@app.post("/teardown")
async def teardown(req: TeardownRequest) -> dict:
    try:
        await _exec.teardown(req.decky_id)
    except Exception as exc:
        log.exception("agent.teardown failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"status": "torn_down", "decky_id": req.decky_id}


@app.post("/self-destruct")
async def self_destruct() -> dict:
    """Stop all DECNET services on this worker and delete the install
    footprint. Called by the master during decommission. Logs under
    /var/log/decnet* are preserved. Fire-and-forget — returns 202 before
    the reaper starts deleting files."""
    try:
        await _exec.self_destruct()
    except Exception as exc:
        log.exception("agent.self_destruct failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"status": "self_destruct_scheduled"}


@app.post("/mutate")
async def mutate(req: MutateRequest) -> dict:
    # Service rotation is routed through the deployer's existing mutate path
    # by the master (worker-side mutate is a redeploy of a single decky with
    # the new service set).  For v1 we accept the request and ask the master
    # to send a full /deploy with the updated DecnetConfig — simpler and
    # avoids duplicating mutation logic on the worker.
    raise HTTPException(
        status_code=501,
        detail="Per-decky mutate is performed via /deploy with updated services",
    )
