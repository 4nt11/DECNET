# SPDX-License-Identifier: AGPL-3.0-or-later
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo
from decnet.web.db.models import CredentialReuseResponse

router = APIRouter()


@router.get(
    "/credential-reuse",
    response_model=CredentialReuseResponse,
    tags=["Credentials"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.list_credential_reuse")
async def list_credential_reuse(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    min_target_count: int = Query(2, ge=2, le=2147483647),
    secret_kind: Optional[str] = None,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Paged list of credential-reuse findings ordered by target_count desc.

    Each row collapses every Credential capture sharing the same secret
    + principal across distinct (decky, service) pairs into a single
    finding with the union of attacker UUIDs/IPs and reach.
    """
    def _norm(v: Optional[str]) -> Optional[str]:
        if v in (None, "null", "NULL", "undefined", ""):
            return None
        return v

    kind = _norm(secret_kind)
    total, data = await repo.list_credential_reuses(
        limit=limit,
        offset=offset,
        min_target_count=min_target_count,
        secret_kind=kind,
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "data": data,
    }


@router.get(
    "/credential-reuse/{reuse_id}",
    tags=["Credentials"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "CredentialReuse row not found"},
    },
)
@_traced("api.get_credential_reuse")
async def get_credential_reuse(
    reuse_id: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """One credential-reuse finding by UUID, or 404."""
    row = await repo.get_credential_reuse_by_id(reuse_id)
    if row is None:
        raise HTTPException(status_code=404, detail="credential_reuse not found")
    return row
