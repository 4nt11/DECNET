"""GET /api/v1/attackers/export/stix — fleet-wide STIX 2.1 bundle.

Returns a self-contained STIX 2.1 Bundle covering every attacker the
instance has observed. Attack-pattern SDOs carry canonical MITRE STIX IDs
and are deduplicated across attackers — consumers who already have the
public ATT&CK bundle won't accumulate duplicates.

Per-tag Sightings, captured Artifacts, and SMTP targets are omitted in
fleet mode. Use GET /api/v1/attackers/{uuid}/export/stix for full fidelity
on a single attacker.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from decnet.telemetry import traced as _traced
from decnet.ttp.stix_export import build_fleet_bundle
from decnet.web.dependencies import require_viewer, repo

router = APIRouter()


@router.get(
    "/attackers/export/stix",
    tags=["Attacker Profiles"],
    response_class=Response,
    responses={
        200: {
            "content": {"application/json": {}},
            "description": "STIX 2.1 bundle for all attackers",
        },
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.attackers.export_stix_fleet")
async def api_export_attackers_stix(
    user: dict[str, Any] = Depends(require_viewer),
) -> Response:
    """Download a STIX 2.1 bundle covering every observed attacker."""
    rows, ttp_by_attacker, obs_by_attacker, fp_by_ip = await _gather_fleet_data()
    bundle = build_fleet_bundle(
        rows=rows,
        ttp_by_attacker=ttp_by_attacker,
        observations_by_attacker=obs_by_attacker,
        fingerprint_bounties_by_ip=fp_by_ip,
    )
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=bundle.serialize(pretty=True, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="decnet-fleet-{ts}.stix.json"'
            ),
        },
    )


async def _gather_fleet_data() -> tuple[
    list[dict[str, Any]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
]:
    import asyncio
    rows, ttp_by_attacker, obs_by_attacker, fp_by_ip = await asyncio.gather(
        repo.get_all_attackers_for_export(),
        repo.get_all_ttp_rollups_for_export(),
        repo.get_all_observations_for_export(),
        repo.get_all_fingerprint_bounties_for_export(),
    )
    return rows, ttp_by_attacker, obs_by_attacker, fp_by_ip
