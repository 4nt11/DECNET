# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST/DELETE /api/v1/deckies/files — generic file drops on deckies.

Wraps :func:`decnet.decky_io.write_file_to_container` /
:func:`decnet.decky_io.delete_file_from_container` so admins can drop
arbitrary bytes at arbitrary paths inside a running decky container —
fleet OR MazeNET — without going through the canary surface.

Auth: ``require_admin`` everywhere (matches every other write op on
deckies; see :mod:`decnet.web.router.fleet.api_mutate_decky`).

Container resolution mirrors the canary path: ``topology_id`` absent
means fleet (``<decky>-ssh``), present routes through
:func:`decnet.decky_io.resolve_decky_container` for the MazeNET
``<decky>-ssh`` / ``decnet_t_<id8>_<decky>`` distinction.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException

from decnet.decky_io import (
    delete_file_from_container,
    resolve_decky_container,
    write_file_to_container,
)
from decnet.logging import get_logger
from decnet.web.db.models import (
    DeckyFileDeleteRequest,
    DeckyFileDropRequest,
    MessageResponse,
)
from decnet.web.dependencies import repo, require_admin

log = get_logger("api.deckies.files")

router = APIRouter(prefix="/deckies/files", tags=["Deckies"])


async def _resolve_container_or_4xx(
    decky_name: str, topology_id: str | None,
) -> str:
    """Resolve to a docker container, mapping LookupError → 404/422."""
    try:
        return await resolve_decky_container(
            repo, decky_name, topology_id=topology_id,
        )
    except LookupError as exc:
        msg = str(exc)
        if topology_id and "topology" in msg and "not found" in msg:
            raise HTTPException(status_code=404, detail=msg) from exc
        raise HTTPException(status_code=422, detail=msg) from exc


@router.post(
    "",
    response_model=MessageResponse,
    status_code=201,
    responses={
        400: {"description": "Invalid request body (bad base64, etc.)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
        409: {"description": "docker exec failed (container down or path unwritable)"},
        422: {"description": "Path validation failed or decky not in topology"},
    },
)
async def api_drop_file(
    req: DeckyFileDropRequest,
    admin: dict = Depends(require_admin),
) -> MessageResponse:
    try:
        content = base64.b64decode(req.content_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400, detail="content_b64 is not valid base64",
        ) from exc

    container = await _resolve_container_or_4xx(req.decky_name, req.topology_id)
    mtime = (
        datetime.now(timezone.utc) + timedelta(seconds=req.mtime_offset)
        if req.mtime_offset
        else None
    )
    success, error = await write_file_to_container(
        container, req.path, content, mode=req.mode, mtime=mtime,
    )
    if not success:
        raise HTTPException(status_code=409, detail=error or "docker exec failed")
    log.info(
        "decky.file.drop decky=%s topology=%s container=%s path=%s bytes=%d by=%s",
        req.decky_name, req.topology_id, container, req.path,
        len(content), admin.get("uuid", "unknown"),
    )
    return MessageResponse(message="ok")


@router.delete(
    "",
    response_model=MessageResponse,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
        422: {"description": "Path validation failed or decky not in topology"},
    },
)
async def api_delete_file(
    req: DeckyFileDeleteRequest,
    admin: dict = Depends(require_admin),
) -> MessageResponse:
    container = await _resolve_container_or_4xx(req.decky_name, req.topology_id)
    success, error = await delete_file_from_container(container, req.path)
    # ``rm -f`` returns 0 even when the file is already gone, so a
    # False here means the docker exec itself failed.  Don't 404 — the
    # caller asked us to ensure absence and we couldn't reach the
    # container.  Surface it as 409.
    if not success:
        raise HTTPException(status_code=409, detail=error or "docker exec failed")
    log.info(
        "decky.file.delete decky=%s topology=%s container=%s path=%s by=%s",
        req.decky_name, req.topology_id, container, req.path,
        admin.get("uuid", "unknown"),
    )
    return MessageResponse(message="ok")
