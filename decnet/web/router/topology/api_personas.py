"""GET/PUT ``/topologies/{id}/personas`` — per-topology email persona pool.

The global pool (``decnet/web/router/emailgen/api_personas.py``) drives
non-MazeNET fleet/SWARM-shard mail deckies.  MazeNET topology mail
deckies use ``Topology.email_personas`` instead — one JSON-serialized
list per topology, parsed by the emailgen scheduler each tick.

This endpoint is the API surface behind the dashboard's per-topology
"Personas" editor.  Reads accept admin or viewer; writes are admin-only.

Concurrency: last-write-wins.  The list is operator-curated and small
(typically <20 entries); no need for optimistic versioning here.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.logging import get_logger
from decnet.realism.personas import EmailPersona, parse_personas
from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_admin, require_viewer

router = APIRouter()
log = get_logger("api.topology.personas")


def _serialize(personas: list[EmailPersona]) -> list[dict[str, Any]]:
    return [p.model_dump(exclude_none=False) for p in personas]


@router.get(
    "/{topology_id}/personas",
    tags=["MazeNET Topologies"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
    },
)
@_traced("api.topology.list_personas")
async def list_topology_personas(
    topology_id: str,
    _viewer: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Return the topology's persona list and its language default.

    ``language_default`` is included so the editor can show which
    language unset entries fall back to — same fallback the scheduler
    applies when building prompts.
    """
    topo = await repo.get_topology(topology_id)
    if topo is None:
        raise HTTPException(status_code=404, detail="Topology not found")
    language_default = topo.get("language_default") or "en"
    personas = parse_personas(
        topo.get("email_personas"), language_default=language_default,
    )
    return {
        "topology_id": topology_id,
        "topology_name": topo.get("name", ""),
        "language_default": language_default,
        "personas": _serialize(personas),
    }


@router.put(
    "/{topology_id}/personas",
    tags=["MazeNET Topologies"],
    responses={
        400: {"description": "Invalid persona payload"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
    },
)
@_traced("api.topology.replace_personas")
async def replace_topology_personas(
    topology_id: str,
    body: dict[str, Any],
    user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Replace the topology's persona list.

    Body shape: ``{"personas": [<EmailPersona>, ...]}``.

    Drop-invalid semantics mirror the global-pool endpoint: bad entries
    are skipped with a warning rather than failing the whole request, but
    a wholly invalid payload returns 400 so a schema mistake doesn't
    silently wipe the list.
    """
    raw = body.get("personas")
    if not isinstance(raw, list):
        raise HTTPException(
            status_code=400, detail="body.personas must be a list",
        )

    topo = await repo.get_topology(topology_id)
    if topo is None:
        raise HTTPException(status_code=404, detail="Topology not found")
    language_default = topo.get("language_default") or "en"

    parsed = parse_personas(raw, language_default=language_default)
    if raw and not parsed:
        raise HTTPException(
            status_code=400,
            detail=(
                "All persona entries failed validation. Required fields: "
                "name, email (user@host.tld), role, tone, mannerisms."
            ),
        )

    serialized = _serialize(parsed)
    payload = json.dumps(serialized, ensure_ascii=False)
    updated = await repo.set_topology_email_personas(topology_id, payload)
    if not updated:
        # Race: row vanished between the get and the update.
        raise HTTPException(status_code=404, detail="Topology not found")

    log.info(
        "api.topology.replace_personas user=%s topology=%s wrote=%d",
        user.get("username", user.get("uuid")), topology_id, len(parsed),
    )
    return {
        "topology_id": topology_id,
        "topology_name": topo.get("name", ""),
        "language_default": language_default,
        "personas": serialized,
    }
