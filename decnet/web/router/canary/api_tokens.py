"""Operator-facing canary token CRUD.

Every body-bearing route documents the 400 error per
:mod:`feedback_schemathesis_400`.  Auth deps:

* writes (POST, DELETE) → :func:`require_admin`
* reads (GET, preview)  → :func:`require_viewer`

The router resolves blobs / instrumenters / generators here, builds
the :class:`CanaryArtifact`, and hands it to the planter.  The
worker is a separate process; it doesn't see this code path.
"""
from __future__ import annotations

from secrets import token_urlsafe
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from decnet.canary import (
    CanaryContext,
    get_generator,
    get_instrumenter,
    pick_instrumenter_for_mime,
    storage,
)
from decnet.canary.base import InstrumenterRejectedError
from decnet.canary.factory import KNOWN_GENERATORS
from decnet.canary.paths import normalize_placement
from decnet.canary import planter
from decnet.logging import get_logger
from decnet.web.db.models import (
    CanaryTokenCreateRequest,
    CanaryTokenResponse,
    CanaryTokensResponse,
    CanaryTriggerResponse,
    CanaryTriggersResponse,
    MessageResponse,
)
from decnet.web.dependencies import repo, require_admin, require_viewer

log = get_logger("api.canary.tokens")

router = APIRouter(prefix="/tokens", tags=["Canary"])


def _http_base() -> str:
    import os
    return os.environ.get(
        "DECNET_CANARY_HTTP_BASE", "http://localhost:8088",
    ).rstrip("/")


def _dns_zone() -> str:
    import os
    return os.environ.get("DECNET_CANARY_DNS_ZONE", "").strip(".").lower()


def _row_to_response(row: dict[str, Any]) -> CanaryTokenResponse:
    return CanaryTokenResponse(**row)


def _trigger_row_to_response(row: dict[str, Any]) -> CanaryTriggerResponse:
    # Decode raw_headers JSON for the response shape.
    headers = row.get("raw_headers") or "{}"
    try:
        import json
        decoded = json.loads(headers) if isinstance(headers, str) else headers
        if not isinstance(decoded, dict):
            decoded = {}
    except (ValueError, TypeError):
        decoded = {}
    out = dict(row)
    out["headers"] = decoded
    out.pop("raw_headers", None)
    return CanaryTriggerResponse(**out)


# ---------------------------------------------------------- create

@router.post(
    "",
    response_model=CanaryTokenResponse,
    status_code=201,
    responses={
        400: {"description": "Invalid token request (missing/conflicting fields, bad path, instrumenter rejection)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Referenced blob not found"},
    },
)
async def api_create_token(
    req: CanaryTokenCreateRequest,
    admin: dict = Depends(require_admin),
) -> CanaryTokenResponse:
    # Exactly one of blob_uuid / generator must be set.
    if bool(req.blob_uuid) == bool(req.generator):
        raise HTTPException(
            status_code=400,
            detail="provide exactly one of blob_uuid or generator",
        )
    try:
        placement_path = normalize_placement(req.placement_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    slug = token_urlsafe(16)
    ctx = CanaryContext(
        callback_token=slug, http_base=_http_base(), dns_zone=_dns_zone(),
    )

    if req.generator:
        if req.generator not in KNOWN_GENERATORS:
            raise HTTPException(
                status_code=400,
                detail=f"unknown generator: {req.generator!r}",
            )
        generator = get_generator(req.generator)
        artifact = generator.generate(ctx)
        instrumenter_name = None
    else:
        # Upload-driven token.
        if req.blob_uuid is None:
            raise HTTPException(status_code=400, detail="blob_uuid required")
        blob = await repo.get_canary_blob(req.blob_uuid)
        if blob is None:
            raise HTTPException(status_code=404, detail="blob not found")
        try:
            blob_bytes = storage.read_blob(blob["sha256"])
        except FileNotFoundError as e:
            raise HTTPException(
                status_code=410,
                detail="blob bytes missing on disk; please re-upload",
            ) from e
        instrumenter_name = pick_instrumenter_for_mime(blob["content_type"])
        ins = get_instrumenter(instrumenter_name)
        try:
            artifact = ins.instrument(blob_bytes, ctx, target_path=placement_path)
        except InstrumenterRejectedError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    artifact.path = placement_path
    token_uuid = str(uuid4())
    kind = req.kind
    await repo.create_canary_token({
        "uuid": token_uuid,
        "kind": kind,
        "decky_name": req.decky_name,
        "blob_uuid": req.blob_uuid,
        "instrumenter": instrumenter_name,
        "generator": req.generator,
        "placement_path": placement_path,
        "callback_token": slug,
        "secret_seed": slug,
        "created_by": admin.get("uuid", "unknown"),
        "state": "planted",
    })
    await planter.plant(req.decky_name, artifact, token_uuid=token_uuid, repo=repo)
    row = await repo.get_canary_token(token_uuid)
    if row is None:
        raise HTTPException(status_code=500, detail="token insert succeeded but row not found")
    return _row_to_response(row)


# ---------------------------------------------------------- list / detail

@router.get(
    "",
    response_model=CanaryTokensResponse,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
async def api_list_tokens(
    decky_name: str | None = Query(default=None),
    state: str | None = Query(default=None),
    kind: str | None = Query(default=None),
    viewer: dict = Depends(require_viewer),
) -> CanaryTokensResponse:
    rows = await repo.list_canary_tokens(
        decky_name=decky_name, state=state, kind=kind,
    )
    return CanaryTokensResponse(
        tokens=[_row_to_response(r) for r in rows],
        total=len(rows),
    )


@router.get(
    "/{uuid}",
    response_model=CanaryTokenResponse,
    responses={
        404: {"description": "Token not found"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
async def api_get_token(
    uuid: str,
    viewer: dict = Depends(require_viewer),
) -> CanaryTokenResponse:
    row = await repo.get_canary_token(uuid)
    if row is None:
        raise HTTPException(status_code=404, detail="token not found")
    return _row_to_response(row)


# ---------------------------------------------------------- preview

@router.get(
    "/{uuid}/preview",
    response_class=Response,
    responses={
        200: {"description": "Instrumented bytes (raw)"},
        404: {"description": "Token not found"},
        409: {"description": "Token has no preview-able bytes (passive aws_creds, etc.)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
async def api_preview_token(
    uuid: str,
    admin: dict = Depends(require_admin),
) -> Response:
    """Return the instrumented bytes the planter dropped on the decky.

    Re-derived deterministically from the row's ``secret_seed`` —
    we don't store the rendered bytes server-side.  Lets operators
    diff-check what we wrote without ``docker exec``-ing into the
    container.
    """
    row = await repo.get_canary_token(uuid)
    if row is None:
        raise HTTPException(status_code=404, detail="token not found")
    ctx = CanaryContext(
        callback_token=row["callback_token"],
        http_base=_http_base(),
        dns_zone=_dns_zone(),
    )
    if row["generator"]:
        artifact = get_generator(row["generator"]).generate(ctx)
    elif row["blob_uuid"] and row["instrumenter"]:
        blob = await repo.get_canary_blob(row["blob_uuid"])
        if blob is None:
            raise HTTPException(
                status_code=409,
                detail="blob has been deleted; preview unavailable",
            )
        try:
            blob_bytes = storage.read_blob(blob["sha256"])
        except FileNotFoundError as e:
            raise HTTPException(
                status_code=409,
                detail="blob bytes missing on disk",
            ) from e
        ins = get_instrumenter(row["instrumenter"])
        try:
            artifact = ins.instrument(
                blob_bytes, ctx, target_path=row["placement_path"],
            )
        except InstrumenterRejectedError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
    else:
        raise HTTPException(
            status_code=409,
            detail="token has neither generator nor instrumenter — nothing to preview",
        )
    return Response(content=artifact.content, media_type="application/octet-stream")


# ---------------------------------------------------------- triggers

@router.get(
    "/{uuid}/triggers",
    response_model=CanaryTriggersResponse,
    responses={
        404: {"description": "Token not found"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
async def api_list_triggers(
    uuid: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    viewer: dict = Depends(require_viewer),
) -> CanaryTriggersResponse:
    row = await repo.get_canary_token(uuid)
    if row is None:
        raise HTTPException(status_code=404, detail="token not found")
    rows = await repo.list_canary_triggers(uuid, limit=limit, offset=offset)
    return CanaryTriggersResponse(
        triggers=[_trigger_row_to_response(r) for r in rows],
        total=len(rows),
    )


# ---------------------------------------------------------- revoke

@router.delete(
    "/{uuid}",
    response_model=MessageResponse,
    responses={
        404: {"description": "Token not found"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
async def api_revoke_token(
    uuid: str,
    admin: dict = Depends(require_admin),
) -> MessageResponse:
    row = await repo.get_canary_token(uuid)
    if row is None:
        raise HTTPException(status_code=404, detail="token not found")
    await planter.revoke(
        row["decky_name"], row["placement_path"],
        token_uuid=uuid, repo=repo,
    )
    return MessageResponse(message="ok")
