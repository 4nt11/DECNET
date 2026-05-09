"""GET /api/v1/attackers/{uuid}/attribution — per-primitive
attribution state for one attacker.

Returns the merger output produced by
:mod:`decnet.correlation.attribution_worker` over the observations
linked to this attacker's identity. Pre-clusterer (v0), every
attacker has a 1:1 stub identity, so the returned set is the merger
output for the single attacker; v1's clusterer makes the rollup
cross-attacker.

Empty ``primitives`` is the honest answer when:

- The attribution worker has not yet processed an observation for
  this attacker (race with first-sight + behave-shell ingest), OR
- The attacker has fewer than ``MIN_OBSERVATIONS_FOR_STATE``
  observations of any primitive — every state row would be ``unknown``,
  and the worker writes those, so the empty case is genuinely "engine
  hasn't run yet".

The response includes ``identity_uuid`` so AttackerDetail can render
a "rolls up to identity X" hint ahead of the v1 IdentityDetail wire-
up — we don't pretend the keying is per-attacker.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

from ._guards import get_attacker_or_404

router = APIRouter()


@router.get(
    "/attackers/{uuid}/attribution",
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Attacker not found"},
    },
)
@_traced("api.get_attacker_attribution")
async def get_attacker_attribution(
    uuid: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Return per-primitive attribution state for an attacker.

    Shape::

        {
            "identity_uuid": "abc123..." | null,
            "primitives": [
                {
                    "primitive": "motor.input_modality",
                    "current_value": "pasted",
                    "state": "stable",
                    "confidence": 0.91,
                    "observation_count": 7,
                    "last_change_ts": 1714521660.456,
                    "last_observation_ts": 1714521660.456
                },
                ...
            ]
        }
    """
    attacker = await get_attacker_or_404(uuid)
    identity_uuid = attacker.get("identity_id") if isinstance(attacker, dict) else None
    if not identity_uuid:
        # Attacker exists but the attribution worker has not yet
        # stamped a stub identity on first observation.
        return {"identity_uuid": None, "primitives": []}

    rows = await repo.get_attribution_state_for_identity(identity_uuid)
    primitives = [
        {
            "primitive": row["primitive"],
            "current_value": row["current_value"],
            "state": row["state"],
            "confidence": row["confidence"],
            "observation_count": row["observation_count"],
            "last_change_ts": row["last_change_ts"],
            "last_observation_ts": row["last_observation_ts"],
        }
        for row in rows
    ]
    return {"identity_uuid": identity_uuid, "primitives": primitives}
