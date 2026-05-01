"""GET/PUT ``/api/v1/realism/config`` — operator-tunable realism knobs.

Today only the planner's content-class weights + canary probability
are exposed. The wire shape mirrors what
:func:`decnet.realism.planner.current_payload` produces and
:func:`decnet.realism.planner.apply_payload` consumes.

Reads accept viewer; writes are admin (writes mutate sampling
behaviour across the whole orchestrator fleet, same trust level as
the persona-pool surface).

The orchestrator worker periodically re-loads from the
``realism_config`` table; the API process applies overrides locally
on PUT so the GET-after-PUT round-trip reflects the change without
waiting for the orchestrator's next refresh tick.
"""
from __future__ import annotations

import json
import threading
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.logging import get_logger
from decnet.realism import planner
from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_admin, require_viewer

router = APIRouter()
log = get_logger("api.realism.config")

_CONFIG_KEY = "weights"
_hydrated = False
_hydrate_lock = threading.Lock()


@router.get(
    "/realism/config",
    tags=["Realism"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.realism.get_config")
async def get_config(
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Return the live planner config in this API process.

    Note: the API process and the orchestrator worker each carry their
    own in-memory copy of the planner config. After a fresh API
    restart the ``realism_config`` row is loaded into this process the
    first time GET is called; subsequent reads are local.
    """
    global _hydrated
    if not _hydrated:
        with _hydrate_lock:
            if not _hydrated:
                row = await repo.get_realism_config(_CONFIG_KEY)
                if row is not None:
                    try:
                        stored = json.loads(row.get("value") or "{}")
                        if isinstance(stored, dict):
                            planner.apply_payload(stored)
                    except (json.JSONDecodeError, ValueError) as exc:
                        log.warning(
                            "api.realism.get_config: stored payload invalid, "
                            "serving defaults: %s", exc,
                        )
                _hydrated = True
    return planner.current_payload()


@router.put(
    "/realism/config",
    tags=["Realism"],
    responses={
        400: {"description": "Invalid config payload"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.realism.put_config")
async def put_config(
    body: dict[str, Any],
    user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Replace (partial) planner config and persist to ``realism_config``.

    Body shape (all fields optional — unset fields keep current value):

    * ``user_class_weights``: ``[{"content_class": "note", "weight": 30}, ...]``
    * ``system_class_weights``: same shape
    * ``canary_class_weights``: same shape
    * ``canary_probability``: float in [0.0, 1.0]

    Validation: any structural failure raises 400 *before* the rebind,
    so the live config never goes torn.
    """
    global _hydrated
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="body must be an object")

    try:
        dropped = planner.apply_payload(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    _hydrated = True

    # Persist what the planner now reflects (keeps DB in sync with the
    # in-memory state — partial bodies merge into prior config).
    snapshot = planner.current_payload()
    await repo.set_realism_config(_CONFIG_KEY, json.dumps(snapshot))

    log.info(
        "api.realism.put_config user=%s canary_probability=%.4f",
        user.get("username", user.get("uuid")),
        snapshot["canary_probability"],
    )
    response: dict[str, Any] = dict(snapshot)
    if dropped:
        response["dropped_entries"] = dropped
    return response
