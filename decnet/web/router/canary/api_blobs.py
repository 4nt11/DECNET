"""Operator-uploaded canary blob CRUD.

Three endpoints:

* ``POST /blobs`` — multipart upload; sniffs MIME from the magic
  bytes (no python-magic dependency), persists to disk under the
  sha256 hash, returns the (possibly pre-existing) row.
* ``GET /blobs`` — list all blobs with their live token reference
  count.
* ``DELETE /blobs/{uuid}`` — refcount-aware delete; returns 409 if
  any token still references the blob.

Admin-gated: blobs are operator-supplied content that may carry
sensitive material (real-looking financial reports, etc.); listing
them and deleting them is an admin operation.  Reading them via the
preview path is also admin-gated.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from decnet.canary import storage
from decnet.logging import get_logger
from decnet.web.db.models import (
    CanaryBlobResponse,
    CanaryBlobsResponse,
    MessageResponse,
)
from decnet.web.dependencies import repo, require_admin

log = get_logger("api.canary.blobs")

router = APIRouter(prefix="/blobs", tags=["Canary"])


# --- MIME sniffing (stdlib-only, replaces python-magic) -------------------
#
# The DOCX/XLSX/PDF/PNG/JPEG/GIF/HTML/JSON/YAML space covers everything
# our instrumenters know how to mutate.  Anything else falls through to
# ``application/octet-stream`` and the API routes the token to the
# ``passthrough`` instrumenter.

_MAGIC_TABLE: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"%PDF-", "application/pdf"),
    # OOXML (DOCX/XLSX) starts with PK\x03\x04 but so do plain zips.
    # We disambiguate by Content_Types entry below.
    (b"<!DOCTYPE", "text/html"),
    (b"<html", "text/html"),
    (b"<HTML", "text/html"),
    (b"<?xml", "application/xml"),
)


def _sniff_mime(filename: str, head: bytes) -> str:
    for marker, mime in _MAGIC_TABLE:
        if head.startswith(marker):
            return mime
    if head[:4] == b"PK\x03\x04":
        # OOXML alias detection: peek for the document-specific Override
        # in [Content_Types].xml. We only need to look at the first
        # block; the central directory comes later.
        if b"wordprocessingml" in head:
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if b"spreadsheetml" in head:
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return "application/zip"
    # Plaintext heuristic: if the head decodes as printable utf-8 we
    # call it text/plain — that's good enough to route to the plain
    # instrumenter, which also handles json/yaml/toml.
    try:
        head.decode("utf-8")
        if all(b in (0x09, 0x0A, 0x0D) or b >= 0x20 for b in head[:128]):
            lf = filename.lower()
            if lf.endswith((".json",)):
                return "application/json"
            if lf.endswith((".yaml", ".yml")):
                return "application/yaml"
            if lf.endswith((".toml",)):
                return "application/toml"
            return "text/plain"
    except UnicodeDecodeError:
        pass
    return "application/octet-stream"


def _row_to_response(row: dict[str, Any]) -> CanaryBlobResponse:
    return CanaryBlobResponse(**row)


@router.post(
    "",
    response_model=CanaryBlobResponse,
    status_code=201,
    responses={
        400: {"description": "Empty file or unreadable upload"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
async def api_upload_blob(
    file: UploadFile = File(...),
    admin: dict = Depends(require_admin),
) -> CanaryBlobResponse:
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="uploaded file is empty")
    sniffed = _sniff_mime(file.filename or "", content[:1024])
    sha, _path, size = storage.write_blob(content)
    row = await repo.upsert_canary_blob({
        "sha256": sha,
        "filename": file.filename or "(unnamed)",
        "content_type": sniffed,
        "size_bytes": size,
        "uploaded_by": admin.get("uuid", "unknown"),
        "uploaded_at": datetime.now(timezone.utc),
    })
    row.setdefault("token_count", 0)
    return _row_to_response(row)


@router.get(
    "",
    response_model=CanaryBlobsResponse,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
async def api_list_blobs(
    admin: dict = Depends(require_admin),
) -> CanaryBlobsResponse:
    rows = await repo.list_canary_blobs()
    return CanaryBlobsResponse(
        blobs=[_row_to_response(r) for r in rows],
        total=len(rows),
    )


@router.delete(
    "/{uuid}",
    response_model=MessageResponse,
    responses={
        404: {"description": "Blob not found"},
        409: {"description": "Blob still referenced by a token"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
async def api_delete_blob(
    uuid: str,
    admin: dict = Depends(require_admin),
) -> MessageResponse:
    existing = await repo.get_canary_blob(uuid)
    if existing is None:
        raise HTTPException(status_code=404, detail="blob not found")
    deleted = await repo.delete_canary_blob(uuid)
    if not deleted:
        raise HTTPException(
            status_code=409,
            detail="blob is still referenced by one or more tokens",
        )
    # DB row is gone; best-effort unlink the bytes on disk.  A failure
    # here leaves a recoverable orphan, never a dangling DB ref.
    storage.unlink_blob(existing["sha256"])
    return MessageResponse(message="ok")
