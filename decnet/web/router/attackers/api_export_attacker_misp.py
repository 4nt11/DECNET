"""GET /api/v1/attackers/{uuid}/export/misp — MISP event for one attacker.

Converts the attacker's STIX 2.1 bundle to a MISP event JSON file via
misp-stix (ExternalSTIX2toMISPParser). Download the result and import it
into any MISP instance via "Import from MISP JSON".
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo

router = APIRouter()


async def _none() -> None:
    return None


@router.get(
    "/attackers/{uuid}/export/misp",
    tags=["Attacker Profiles"],
    response_class=Response,
    responses={
        200: {
            "content": {"application/json": {}},
            "description": "MISP event for the attacker",
        },
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Attacker not found"},
    },
)
@_traced("api.attackers.export_misp")
async def api_export_attacker_misp(
    uuid: str,
    user: dict[str, Any] = Depends(require_viewer),
) -> Response:
    """Download a MISP event JSON for one attacker."""
    attacker = await repo.get_attacker_by_uuid(uuid)
    if not attacker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown attacker uuid: {uuid!r}",
        )

    identity_coro = (
        repo.get_identity_by_uuid(attacker["identity_id"])
        if attacker.get("identity_id")
        else _none()
    )
    results = await asyncio.gather(
        repo.get_attacker_behavior(uuid),
        identity_coro,
        repo.get_attacker_intel_by_uuid(uuid),
        repo.list_techniques_by_attacker(uuid),
        repo.list_ttp_tags_by_attacker(uuid),
        repo.get_attacker_artifacts(uuid),
        repo.list_smtp_targets(uuid),
        repo.list_attacker_commands_deduped(uuid),
        repo.list_observations_by_attacker(uuid),
        repo.get_fingerprint_bounties_by_ip(attacker["ip"]),
    )
    behavior = cast(dict[str, Any] | None, results[0])
    identity = cast(dict[str, Any] | None, results[1])
    intel = cast(dict[str, Any] | None, results[2])
    technique_rollup = cast(list[Any], results[3])
    raw_tags = cast(list[dict[str, Any]], results[4])
    artifacts = cast(list[dict[str, Any]], results[5])
    smtp_targets = cast(list[dict[str, Any]], results[6])
    commands = cast(list[str], results[7])
    observations = cast(list[dict[str, Any]], results[8])
    fingerprint_bounties = cast(list[dict[str, Any]], results[9])

    from decnet.ttp.misp_export import build_attacker_misp_event  # heavy — lazy on first call
    event = build_attacker_misp_event(
        attacker=attacker,
        behavior=behavior,
        identity=identity,
        intel=intel,
        technique_rollup=[
            r.model_dump() if hasattr(r, "model_dump") else dict(r)
            for r in technique_rollup
        ],
        raw_tags=raw_tags,
        artifacts=artifacts,
        smtp_targets=smtp_targets,
        commands=commands,
        observations=observations,
        fingerprint_bounties=fingerprint_bounties,
    )
    return Response(
        content=json.dumps(event, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="decnet-attacker-{uuid[:8]}.misp.json"'
            ),
        },
    )
