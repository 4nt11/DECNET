# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET/PUT ``/api/v1/realism/personas`` — global persona pool CRUD.

The "global pool" is a JSON file consumed by the realism content
engine for fleet (MACVLAN/IPVLAN) and SWARM-shard deckies — see
:mod:`decnet.realism.personas_pool`.  MazeNET topology deckies use
``Topology.email_personas`` instead and are configured per-topology
elsewhere.

This endpoint is the API surface behind the dashboard's "Persona
Generation" page.  Reads accept admin or viewer; writes are admin-only
because the persistence target is a config file the worker reads on
its hot path.

Concurrency: last-write-wins.  The pool is operator-curated and small
(<50 entries typically); the cost of a stronger model isn't justified.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.logging import get_logger
from decnet.realism import personas_pool as global_pool
from decnet.realism.personas import EmailPersona, parse_personas
from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_admin, require_viewer
from decnet.web.db.models.common import MessageResponse  # noqa: F401 - response shape

router = APIRouter()
log = get_logger("api.realism.personas")


def _serialize(personas: list[EmailPersona]) -> list[dict[str, Any]]:
    """Pydantic → plain dicts for the response body."""
    return [p.model_dump(exclude_none=False) for p in personas]


@router.get(
    "/realism/personas",
    tags=["Emailgen"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.realism.list_personas")
async def list_personas(
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Return the current global persona pool + the resolved file path.

    The ``path`` field lets the dashboard show operators where the file
    lives on disk so a CLI-driven backup / git-tracked workflow stays
    discoverable.
    """
    # Reset the in-process cache before reading so a fresh CLI-driven
    # ``decnet realism import-personas`` shows up immediately rather
    # than waiting on the worker's mtime check.
    global_pool.reset_cache()
    personas = global_pool.load()
    return {
        "path": str(global_pool.resolve_path()),
        "personas": _serialize(personas),
    }


@router.put(
    "/realism/personas",
    tags=["Emailgen"],
    responses={
        400: {"description": "Invalid persona payload"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.realism.replace_personas")
async def replace_personas(
    body: dict[str, Any],
    user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Replace the entire global pool with the supplied list.

    Body shape: ``{"personas": [<EmailPersona>, ...]}``.

    Validation is the same path the worker uses (``parse_personas``):
    invalid entries are dropped with a warning rather than failing the
    whole request — operators see exactly what landed by reading back
    the GET response.  An entirely-invalid payload returns 400.
    """
    raw = body.get("personas")
    if not isinstance(raw, list):
        raise HTTPException(
            status_code=400,
            detail="body.personas must be a list",
        )

    parsed = parse_personas(raw)
    if raw and not parsed:
        # Operator sent a non-empty list and *every* entry was invalid —
        # almost certainly a schema mistake on their side; fail loudly
        # rather than silently writing an empty pool.
        raise HTTPException(
            status_code=400,
            detail=(
                "All persona entries failed validation. Required fields: "
                "name, email (user@host.tld), role, tone, mannerisms."
            ),
        )

    dest = global_pool.resolve_path()
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            json.dumps(_serialize(parsed), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        # Most common cause on dev boxes: ``/etc/decnet`` exists but is
        # not writable by the API process.  Surface a 500 with the
        # actionable hint instead of leaking a traceback.
        log.warning(
            "api.realism.replace_personas write failed path=%s err=%s",
            dest, exc,
        )
        raise HTTPException(
            status_code=500,
            detail=(
                f"Could not write persona pool at {dest}: {exc.strerror or exc}. "
                f"Set DECNET_EMAILGEN_PERSONAS to a writable path "
                f"(e.g. ~/.decnet/email_personas.json) and restart the API."
            ),
        ) from exc
    global_pool.reset_cache()
    log.info(
        "api.realism.replace_personas user=%s wrote=%d path=%s",
        user.get("username", user.get("uuid")), len(parsed), dest,
    )
    return {
        "path": str(dest),
        "personas": _serialize(parsed),
    }
