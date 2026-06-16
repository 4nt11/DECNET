# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/attackers/export/misp — fleet-wide MISP collection.

Returns a MISP collection JSON ({"response": [event, ...]}) with one event
per observed attacker, suitable for bulk import into a MISP instance via
"Import from MISP JSON" or the MISP REST /events/import endpoint.

Per-tag Sightings, captured Artifacts, and SMTP targets are omitted in
fleet mode. Use GET /api/v1/attackers/{uuid}/export/misp for full fidelity
on a single attacker.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo

router = APIRouter()


@router.get(
    "/attackers/export/misp",
    tags=["Attacker Profiles"],
    response_class=Response,
    responses={
        200: {
            "content": {"application/json": {}},
            "description": "MISP collection for all attackers",
        },
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.attackers.export_misp_fleet")
async def api_export_attackers_misp(
    user: dict[str, Any] = Depends(require_viewer),
) -> Response:
    """Download a MISP collection JSON covering every observed attacker."""
    rows, ttp_by_attacker, obs_by_attacker, fp_by_ip = await asyncio.gather(
        repo.get_all_attackers_for_export(),
        repo.get_all_ttp_rollups_for_export(),
        repo.get_all_observations_for_export(),
        repo.get_all_fingerprint_bounties_for_export(),
    )
    from decnet.ttp.misp_export import build_fleet_misp_collection  # heavy — lazy on first call
    collection = build_fleet_misp_collection(
        rows=rows,
        ttp_by_attacker=ttp_by_attacker,
        observations_by_attacker=obs_by_attacker,
        fingerprint_bounties_by_ip=fp_by_ip,
    )
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=json.dumps(collection, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="decnet-fleet-{ts}.misp.json"'
            ),
        },
    )
