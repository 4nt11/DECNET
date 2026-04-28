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

import asyncio
import os
import pathlib
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import contextlib

from decnet.agent import executor as _exec
from decnet.agent import heartbeat as _heartbeat
from decnet.agent import topology_ops as _topology_ops
from decnet.bus.factory import get_bus
from decnet.bus.publish import run_health_heartbeat
from decnet.swarm.pki import DEFAULT_AGENT_DIR
from decnet.agent.topology_store import AlreadyApplied, TopologyStore
from decnet.config import DecnetConfig
from decnet.logging import get_logger
from decnet.topology.validate import ValidationError

log = get_logger("agent.app")


def _resolve_agent_dir() -> pathlib.Path:
    env = os.environ.get("DECNET_AGENT_DIR")
    if env:
        return pathlib.Path(env)
    system = pathlib.Path("/etc/decnet/agent")
    if system.exists():
        return system
    return DEFAULT_AGENT_DIR


# Module-level singleton.  Created lazily on first use so tests can
# monkeypatch DECNET_AGENT_DIR before the store binds to a path.
_topology_store: Optional[TopologyStore] = None


def _store() -> TopologyStore:
    global _topology_store
    if _topology_store is None:
        _topology_store = TopologyStore(_resolve_agent_dir() / "topology.db")
    return _topology_store


_collector_task: Optional[asyncio.Task] = None


def _ensure_collector_started() -> None:
    """Spawn the log collector on demand — called from /topology/apply
    after a successful materialise.  We must NOT start this in the
    lifespan hook: the agent's boot invariant is "never touch docker
    until master tells us to" (see tests/swarm/test_agent_no_auto_restore.py).

    The collector watches ``decnet.topology.service=true`` labels via
    docker events, writing RFC 5424 lines to ``DECNET_AGENT_LOG_FILE``
    which the forwarder ships to the master over syslog-TLS.  Idempotent:
    subsequent calls while the task is still running are no-ops.
    """
    global _collector_task
    if _collector_task is not None and not _collector_task.done():
        return
    from decnet.env import DECNET_AGENT_LOG_FILE

    try:
        from decnet.collector.worker import log_collector_worker
    except Exception:  # noqa: BLE001 — docker may be unavailable on dev
        log.warning(
            "agent log collector not starting — collector worker import failed",
            exc_info=True,
        )
        return
    _collector_task = asyncio.create_task(
        log_collector_worker(DECNET_AGENT_LOG_FILE),
        name="agent-log-collector",
    )
    log.info("agent log collector started log_file=%s", DECNET_AGENT_LOG_FILE)


_bus_heartbeat_task: Optional[asyncio.Task] = None


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Best-effort: if identity/bundle plumbing isn't configured (e.g. dev
    # runs or non-enrolled hosts), heartbeat.start() is a silent no-op.
    _heartbeat.start()

    # Host-local bus heartbeat (system.agent.health).  Separate channel
    # from the mTLS master-facing heartbeat above; this one lets peers on
    # the same host (dashboard, updater) see the agent is alive without
    # hitting its HTTPS endpoint.  Bus-disabled path is a no-op loop.
    bus = None
    try:
        bus = get_bus(client_name="agent")
        await bus.connect()
    except Exception as exc:  # noqa: BLE001
        log.warning("agent: bus unavailable, skipping health heartbeat: %s", exc)
        bus = None

    global _bus_heartbeat_task
    _bus_heartbeat_task = asyncio.create_task(
        run_health_heartbeat(bus, "agent"),
        name="agent-bus-heartbeat",
    )

    try:
        yield
    finally:
        await _heartbeat.stop()
        if _bus_heartbeat_task is not None:
            _bus_heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await _bus_heartbeat_task
            _bus_heartbeat_task = None
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()
        global _collector_task
        if _collector_task is not None and not _collector_task.done():
            _collector_task.cancel()
            try:
                await _collector_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        _collector_task = None
        global _topology_store
        if _topology_store is not None:
            _topology_store.close()
            _topology_store = None


app = FastAPI(
    title="DECNET SWARM Agent",
    version="0.1.0",
    docs_url=None,    # no interactive docs on worker — narrow attack surface
    redoc_url=None,
    openapi_url=None,
    lifespan=_lifespan,
    responses={
        400: {"description": "Malformed request body"},
        500: {"description": "Executor error"},
    },
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


@app.post(
    "/deploy",
    responses={500: {"description": "Deployer raised an exception materialising the config"}},
)
async def deploy(req: DeployRequest) -> dict:
    try:
        await _exec.deploy(req.config, dry_run=req.dry_run, no_cache=req.no_cache)
    except Exception as exc:
        log.exception("agent.deploy failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"status": "deployed", "deckies": len(req.config.deckies)}


@app.post(
    "/teardown",
    responses={500: {"description": "Teardown raised an exception"}},
)
async def teardown(req: TeardownRequest) -> dict:
    try:
        await _exec.teardown(req.decky_id)
    except Exception as exc:
        log.exception("agent.teardown failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"status": "torn_down", "decky_id": req.decky_id}


@app.post(
    "/self-destruct",
    responses={500: {"description": "Reaper could not be scheduled"}},
)
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


# ------------------------------------------------------- topology endpoints


class ApplyTopologyRequest(BaseModel):
    hydrated: dict[str, Any] = Field(
        ..., description="Hydrated topology dict from master.persistence.hydrate()"
    )
    version_hash: str = Field(
        ..., description="Master's canonical_hash(hydrated); must match ours"
    )


class TeardownTopologyRequest(BaseModel):
    topology_id: str = Field(..., description="Topology UUID to dismantle")


@app.post(
    "/topology/apply",
    responses={
        400: {"description": "Malformed hydrated topology or hash mismatch"},
        409: {"description": "A different topology is already applied"},
        500: {"description": "Docker or compose raised while applying"},
    },
)
async def topology_apply(req: ApplyTopologyRequest) -> dict:
    store = _store()
    try:
        await _topology_ops.apply(req.hydrated, req.version_hash, store)
    except _topology_ops.HashMismatch as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except AlreadyApplied as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        log.exception("agent.topology_apply failed")
        topology_id = (req.hydrated.get("topology") or {}).get("id")
        if topology_id:
            try:
                store.record_error(
                    str(topology_id), str(exc)[:500], hydrated=req.hydrated,
                )
            except Exception:  # noqa: BLE001 — don't mask original failure
                log.exception("failed to record apply error")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    _ensure_collector_started()
    return {"status": "applied", "version_hash": req.version_hash}


@app.post(
    "/topology/teardown",
    responses={500: {"description": "Docker or compose raised while tearing down"}},
)
async def topology_teardown(req: TeardownTopologyRequest) -> dict:
    try:
        await _topology_ops.teardown(req.topology_id, _store())
    except Exception as exc:
        log.exception("agent.topology_teardown failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"status": "torn_down", "topology_id": req.topology_id}


@app.get("/topology/state")
async def topology_state() -> dict:
    return _topology_ops.state(_store())


@app.post(
    "/mutate",
    responses={501: {"description": "Worker-side mutate not yet implemented"}},
)
async def mutate(req: MutateRequest) -> dict:
    # TODO: implement worker-side mutate. Currently the master performs
    # mutation by re-sending a full /deploy with the updated DecnetConfig;
    # this avoids duplicating mutation logic on the worker for v1. When
    # ready, replace the 501 with a real redeploy-of-a-single-decky path.
    raise HTTPException(
        status_code=501,
        detail="Per-decky mutate is performed via /deploy with updated services",
    )
