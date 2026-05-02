"""``GET /api/v1/ttp/tags/by-{scope}/{uuid}/{technique_id}``.

Backs the operator-facing TTP inspector — when a user clicks a
technique row in :class:`TTPsObservedSection`, the UI fetches the raw
:class:`TTPTag` rows that produced the rollup and renders the
``evidence`` JSON, ``rule_id`` / ``rule_version``, ``source_kind`` /
``source_id``, ``confidence``, and ``created_at`` in a side drawer.
The point is to answer "what made the engine flag this technique?"
without exposing the operator to a SQL prompt.

Three scopes mirror the rollup endpoints:

* ``identity`` — tags on the identity OR on attackers projecting up.
* ``attacker`` — tags on the attacker (per-IP).
* ``session`` — tags on the session.

Filtered by ``technique_id`` (path) and an optional
``sub_technique_id`` (query). Capped at 200 newest-first rows so a
busy attacker doesn't hose the drawer.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status

from decnet.telemetry import traced as _traced
from decnet.web.db.models import TTPTagDetailRow
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()

_Scope = Literal["identity", "attacker", "session"]


@router.get(
    "/ttp/tags/by-{scope}/{uuid}/{technique_id}",
    tags=["TTP Tagging"],
    response_model=list[TTPTagDetailRow],
    responses={
        400: {"description": "Bad Request (invalid scope or pagination)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Scope target not found"},
    },
)
@_traced("api.ttp.tag_details")
async def api_ttp_tag_details(
    scope: _Scope,
    uuid: str,
    technique_id: str,
    sub_technique_id: str | None = None,
    limit: int = 200,
    user: dict[str, Any] = Depends(require_viewer),
) -> list[TTPTagDetailRow]:
    """Return raw ``ttp_tag`` rows for the (scope, uuid, technique) tuple."""
    if scope not in ("identity", "attacker", "session"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown scope {scope!r}",
        )
    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="limit must be in [1, 1000]",
        )
    rows = await repo.list_tags_by_scope_and_technique(
        scope=scope,
        uuid=uuid,
        technique_id=technique_id,
        sub_technique_id=sub_technique_id,
        limit=limit,
    )
    return [TTPTagDetailRow(**row) for row in rows]
