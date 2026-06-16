# SPDX-License-Identifier: AGPL-3.0-or-later
"""TTP rule catalogue + admin-only state mutations.

Three endpoints in one router:

* ``GET    /api/v1/ttp/rules``                     — viewer-readable rule list
* ``POST   /api/v1/ttp/rules/{rule_id}/state``     — admin: set state
* ``DELETE /api/v1/ttp/rules/{rule_id}/state``     — admin: revert to default

Per the project's "no client-side role checks" rule, the admin guard
is server-side via :func:`require_admin`. Per
``feedback_schemathesis_400.md``, the POST handler parses the body
manually and returns ``400`` on a malformed JSON body so the
documented status code matches reality.
"""
from __future__ import annotations

from typing import Any

import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError

from decnet.telemetry import traced as _traced
from decnet.web.db.models import (
    RuleCatalogueRow,
    RuleStateRequest,
    RuleStateResponse,
)
from decnet.web.dependencies import require_admin, require_viewer

router = APIRouter()


@router.get(
    "/ttp/rules",
    tags=["TTP Tagging"],
    response_model=list[RuleCatalogueRow],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.ttp.list_rules")
async def api_list_rules(
    user: dict[str, Any] = Depends(require_viewer),
) -> list[RuleCatalogueRow]:
    """Operator-facing rule catalogue.

    Reads from the active :class:`RuleStore` (filesystem or database
    per ``DECNET_TTP_RULE_STORE_TYPE``). Each row is a compiled rule
    plus the operational state the store has stamped on it; rules that
    never had a state set come back as the default ``enabled``.
    """
    from decnet.ttp.store.factory import get_rule_store  # noqa: PLC0415

    store = get_rule_store()
    compiled = await store.load_compiled()
    rows: list[RuleCatalogueRow] = []
    for rule in compiled:
        state = rule.state
        rows.append(RuleCatalogueRow(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            name=rule.name,
            description=rule.description,
            state=state.state,
            confidence_max=state.confidence_max,
            expires_at=state.expires_at,
            reason=state.reason,
            set_by=state.set_by,
            set_at=state.set_at,
        ))
    rows.sort(key=lambda r: r.rule_id)
    return rows


@router.post(
    "/ttp/rules/{rule_id}/state",
    tags=["TTP Tagging"],
    response_model=RuleStateResponse,
    responses={
        400: {"description": "Bad Request (malformed JSON or invalid body)"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Rule not found"},
    },
)
@_traced("api.ttp.set_rule_state")
async def api_set_rule_state(
    rule_id: str,
    request: Request,
    admin: dict[str, Any] = Depends(require_admin),
) -> RuleStateResponse:
    """Set operational state (disable / clip / TTL) on a rule.

    Body parse is manual so a malformed JSON body surfaces as the
    documented ``400`` rather than the framework default of ``422``
    (per ``feedback_schemathesis_400.md``).
    """
    try:
        raw = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Body must be valid JSON",
        ) from exc
    try:
        body = RuleStateRequest.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid rule-state body: {exc.errors()}",
        ) from exc

    # Contract phase: no persistence yet (E.1.10 / E.3 lands the repo
    # write). Echo the requested state back so the response shape is
    # exercisable and OpenAPI-stable.
    return RuleStateResponse(
        rule_id=rule_id,
        state=body.state,
        confidence_max=body.confidence_max,
        expires_at=body.expires_at,
        reason=body.reason,
        set_by=str(admin.get("sub", "")),
        set_at=None,
    )


@router.delete(
    "/ttp/rules/{rule_id}/state",
    tags=["TTP Tagging"],
    response_model=RuleStateResponse,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Rule not found"},
    },
)
@_traced("api.ttp.revert_rule_state")
async def api_revert_rule_state(
    rule_id: str,
    admin: dict[str, Any] = Depends(require_admin),
) -> RuleStateResponse:
    """Revert a rule to the default ``enabled`` state."""
    return RuleStateResponse(
        rule_id=rule_id,
        state="enabled",
        confidence_max=None,
        expires_at=None,
        reason=None,
        set_by=str(admin.get("sub", "")),
        set_at=None,
    )
