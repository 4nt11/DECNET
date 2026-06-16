# SPDX-License-Identifier: AGPL-3.0-or-later
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.correlation.event_kinds import bucket_services
from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo

router = APIRouter()


@router.get(
    "/attackers/{uuid}",
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Attacker not found"},
    },
)
@_traced("api.get_attacker_detail")
async def get_attacker_detail(
    uuid: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Retrieve a single attacker profile by UUID (with behavior block)."""
    attacker = await repo.get_attacker_by_uuid(uuid)
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")
    attacker["behavior"] = await repo.get_attacker_behavior(uuid)
    # Scanned vs. interacted-with — computed per-request from the log
    # stream, not persisted. Cheap (DISTINCT bounded by service ×
    # event_type cardinality), and changes to the classifier take effect
    # immediately without a profiler re-tick.
    pairs = await repo.get_attacker_service_activity(uuid)
    attacker["service_activity"] = bucket_services(pairs)
    # Attribution leaks — XFF / Forwarded / X-Real-IP mismatches captured
    # by the HTTP bounty extractor. Cap the returned list at 10 so a
    # rotation attack (100s of forged XFF values) doesn't flood the UI;
    # `ip_leaks_total` carries the unbounded count so the UI can render
    # a ROTATION DETECTED badge when the count crosses a threshold.
    attacker["ip_leaks"] = await repo.get_attacker_ip_leaks(uuid, limit=10)
    attacker["ip_leaks_total"] = await repo.count_attacker_ip_leaks(uuid)
    # BEHAVE-SHELL observations — latest value per primitive for this
    # attacker. Empty dict (rendered as empty list) until the
    # extractor (DEBT-050) lands and starts writing rows. The frontend
    # panel that consumes this ships in BEHAVE-INTEGRATION.md Phase 5.
    latest_per_primitive = await repo.latest_observation_per_primitive(uuid)
    attacker["observations"] = [
        {"primitive": primitive, **payload}
        for primitive, payload in sorted(latest_per_primitive.items())
    ]
    return attacker
