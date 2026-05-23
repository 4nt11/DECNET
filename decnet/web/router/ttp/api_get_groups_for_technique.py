# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/ttp/techniques/{technique_id}/groups — MITRE-tracked groups using *technique_id*.

Read-only reverse-index off the loaded ATT&CK STIX bundle. **NOT an
attribution claim** about a DECNET attacker — given the technique,
return the list of MITRE-tracked intrusion-sets (groups) documented
as using it. The frontend pulls this lazily when the operator
expands a technique panel; payload sizes for large groups (50+ on
some techniques) make embedding on every TTPTagDetailRow wasteful.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from decnet.telemetry import traced as _traced
from decnet.ttp import attack_stix
from decnet.web.dependencies import require_viewer

router = APIRouter()


@router.get(
    "/ttp/techniques/{technique_id}/groups",
    tags=["TTP Tagging"],
    response_model=list[attack_stix.GroupRef],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Unknown technique_id"},
    },
)
@_traced("api.ttp.groups_for_technique")
async def api_groups_for_technique(
    technique_id: str,
    user: dict[str, Any] = Depends(require_viewer),
) -> list[attack_stix.GroupRef]:
    """List MITRE-tracked intrusion-sets that use *technique_id*.

    Sub-techniques are queried directly (no auto-union with the
    parent — matches ATT&CK Navigator semantics). Empty list when
    the technique exists but has no documented groups; 404 when the
    technique_id doesn't resolve in the loaded ATT&CK bundle at all.
    """
    if not attack_stix.technique_exists(technique_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown technique_id: {technique_id!r}",
        )
    return list(attack_stix.groups_using_technique(technique_id))
