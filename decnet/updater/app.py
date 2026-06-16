# SPDX-License-Identifier: AGPL-3.0-or-later
"""Updater FastAPI app — mTLS-protected endpoints for self-update.

Mirrors the shape of ``decnet/agent/app.py``: bare FastAPI, docs disabled,
handlers delegate to ``decnet.updater.executor``.

Mounted by uvicorn via ``decnet.updater.server`` with ``--ssl-cert-reqs 2``,
so every caller already presents a CA-signed cert. On top of that transport
guarantee, the mutating endpoints app-gate the *client* CN to the master
(``decnet-master``, the identity ``UpdaterClient`` presents via
``ensure_master_identity``): a compromised worker/agent cert must never be
able to pip-install and re-exec arbitrary code on a peer worker.
"""
from __future__ import annotations

import asyncio
import contextlib
import os as _os
import pathlib
from contextlib import asynccontextmanager
from typing import Optional

# Importing this shim patches uvicorn so the TLS peer cert lands in the ASGI
# scope, where require_master_cert can read it. Must import before serving.
from decnet.web import _uvicorn_tls_scope  # noqa: F401
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel

from decnet.bus.factory import get_bus
from decnet.bus.publish import run_health_heartbeat
from decnet.logging import get_logger
from decnet.swarm import pki
from decnet.updater import executor as _exec
from decnet.web._mtls import extract_peer_cert

log = get_logger("updater.app")

# Only the master may push code to a worker's updater. UpdaterClient presents
# the master identity (CN=decnet-master); worker/agent certs are rejected.
_PUSHER_CN = "decnet-master"


def require_master_cert(request: Request) -> None:
    """Reject any caller whose client-cert CN is not the master's.

    Transport mTLS has proven the cert is CA-signed; this stops a non-master
    CA-signed cert (e.g. a worker agent's) from driving an update/rollback.
    Fails closed when no cert is present.
    """
    peer = extract_peer_cert(request.scope)
    if peer is None or peer.cn != _PUSHER_CN:
        log.warning("updater: rejected push from cn=%r", peer.cn if peer else None)
        raise HTTPException(status_code=403, detail="master certificate required")


_bus_heartbeat_task: Optional[asyncio.Task] = None


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    # Host-local bus heartbeat (system.updater.health).  Lets the agent
    # and dashboard tell "updater's up" without hitting the HTTPS port.
    # Bus-disabled path is a no-op loop; the updater serves requests
    # either way.
    bus = None
    try:
        bus = get_bus(client_name="updater")
        await bus.connect()
    except Exception as exc:  # noqa: BLE001
        log.warning("updater: bus unavailable, skipping heartbeat: %s", exc)
        bus = None

    global _bus_heartbeat_task
    _bus_heartbeat_task = asyncio.create_task(
        run_health_heartbeat(bus, "updater"),
        name="updater-bus-heartbeat",
    )
    try:
        yield
    finally:
        if _bus_heartbeat_task is not None:
            _bus_heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await _bus_heartbeat_task
            _bus_heartbeat_task = None
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


app = FastAPI(
    title="DECNET Self-Updater",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=_lifespan,
)


class _Config:
    install_dir: pathlib.Path = pathlib.Path(
        _os.environ.get("DECNET_UPDATER_INSTALL_DIR") or str(_exec.DEFAULT_INSTALL_DIR)
    )
    updater_install_dir: pathlib.Path = pathlib.Path(
        _os.environ.get("DECNET_UPDATER_UPDATER_DIR")
        or str(_exec.DEFAULT_INSTALL_DIR / "updater")
    )
    agent_dir: pathlib.Path = pathlib.Path(
        _os.environ.get("DECNET_UPDATER_AGENT_DIR") or str(pki.DEFAULT_AGENT_DIR)
    )


def configure(
    install_dir: pathlib.Path,
    updater_install_dir: pathlib.Path,
    agent_dir: pathlib.Path,
) -> None:
    """Inject paths from the server launcher; must be called before serving."""
    _Config.install_dir = install_dir
    _Config.updater_install_dir = updater_install_dir
    _Config.agent_dir = agent_dir


# ------------------------------------------------------------------- schemas

class RollbackResult(BaseModel):
    status: str
    release: dict
    probe: str


class ReleasesResponse(BaseModel):
    releases: list[dict]


# -------------------------------------------------------------------- routes

@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "role": "updater",
        "releases": [r.to_dict() for r in _exec.list_releases(_Config.install_dir)],
    }


@app.get("/releases")
async def releases(_pusher: None = Depends(require_master_cert)) -> dict:
    return {"releases": [r.to_dict() for r in _exec.list_releases(_Config.install_dir)]}


@app.post("/update")
async def update(
    tarball: UploadFile = File(..., description="tar.gz of the working tree"),
    sha: str = Form("", description="git SHA of the tree for provenance"),
    sha256: str = Form("", description="hex SHA-256 of the tarball bytes; verified before extract"),
    _pusher: None = Depends(require_master_cert),
) -> dict:
    if not sha256:
        # Mandatory: guarantees _verify_tarball_sha256 runs before we extract +
        # pip-install. An update with no integrity check is refused outright.
        raise HTTPException(status_code=400, detail="sha256 of the tarball is required")
    body = await tarball.read()
    try:
        return _exec.run_update(
            body, sha=sha or None,
            expected_sha256=sha256,
            install_dir=_Config.install_dir, agent_dir=_Config.agent_dir,
        )
    except _exec.UpdateError as exc:
        status = 409 if exc.rolled_back else 500
        raise HTTPException(
            status_code=status,
            detail={"error": str(exc), "stderr": exc.stderr, "rolled_back": exc.rolled_back},
        ) from exc


@app.post("/update-self")
async def update_self(
    tarball: UploadFile = File(...),
    sha: str = Form(""),
    sha256: str = Form("", description="hex SHA-256 of the tarball bytes; verified before extract"),
    confirm_self: str = Form("", description="Must be 'true' to proceed"),
    _pusher: None = Depends(require_master_cert),
) -> dict:
    if confirm_self.lower() != "true":
        raise HTTPException(
            status_code=400,
            detail="self-update requires confirm_self=true (no auto-rollback)",
        )
    if not sha256:
        raise HTTPException(status_code=400, detail="sha256 of the tarball is required")
    body = await tarball.read()
    try:
        return _exec.run_update_self(
            body, sha=sha or None,
            updater_install_dir=_Config.updater_install_dir,
            expected_sha256=sha256,
        )
    except _exec.UpdateError as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": str(exc), "stderr": exc.stderr},
        ) from exc


@app.post("/rollback")
async def rollback(_pusher: None = Depends(require_master_cert)) -> dict:
    try:
        return _exec.run_rollback(
            install_dir=_Config.install_dir, agent_dir=_Config.agent_dir,
        )
    except _exec.UpdateError as exc:
        status = 404 if "no previous" in str(exc) else 500
        raise HTTPException(
            status_code=status,
            detail={"error": str(exc), "stderr": exc.stderr},
        ) from exc
