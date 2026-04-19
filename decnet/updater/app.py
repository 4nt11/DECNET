"""Updater FastAPI app — mTLS-protected endpoints for self-update.

Mirrors the shape of ``decnet/agent/app.py``: bare FastAPI, docs disabled,
handlers delegate to ``decnet.updater.executor``.

Mounted by uvicorn via ``decnet.updater.server`` with ``--ssl-cert-reqs 2``;
the CN on the peer cert tells us which endpoints are legal (``updater@*``
only — agent certs are rejected).
"""
from __future__ import annotations

import os as _os
import pathlib

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from decnet.logging import get_logger
from decnet.swarm import pki
from decnet.updater import executor as _exec

log = get_logger("updater.app")

app = FastAPI(
    title="DECNET Self-Updater",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
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
async def releases() -> dict:
    return {"releases": [r.to_dict() for r in _exec.list_releases(_Config.install_dir)]}


@app.post("/update")
async def update(
    tarball: UploadFile = File(..., description="tar.gz of the working tree"),
    sha: str = Form("", description="git SHA of the tree for provenance"),
) -> dict:
    body = await tarball.read()
    try:
        return _exec.run_update(
            body, sha=sha or None,
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
    confirm_self: str = Form("", description="Must be 'true' to proceed"),
) -> dict:
    if confirm_self.lower() != "true":
        raise HTTPException(
            status_code=400,
            detail="self-update requires confirm_self=true (no auto-rollback)",
        )
    body = await tarball.read()
    try:
        return _exec.run_update_self(
            body, sha=sha or None,
            updater_install_dir=_Config.updater_install_dir,
        )
    except _exec.UpdateError as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": str(exc), "stderr": exc.stderr},
        ) from exc


@app.post("/rollback")
async def rollback() -> dict:
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
