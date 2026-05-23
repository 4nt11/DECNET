# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/attackers/export — bulk JSON export of all attacker + intel data."""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()

_SCHEMA_VERSION = "1.0"
_SOURCE = "DECNET Honeypot"


def _shape_observation(row: dict) -> dict:
    intel = row.get("threat_intel")
    return {
        "uuid": row.get("uuid"),
        "ip": row.get("ip"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "identity_id": row.get("identity_id"),
        "event_count": row.get("event_count", 0),
        "service_count": row.get("service_count", 0),
        "decky_count": row.get("decky_count", 0),
        "services": row.get("services", []),
        "deckies": row.get("deckies", []),
        "traversal_path": row.get("traversal_path"),
        "is_traversal": row.get("is_traversal", False),
        "bounty_count": row.get("bounty_count", 0),
        "credential_count": row.get("credential_count", 0),
        "fingerprints": row.get("fingerprints", []),
        "commands": row.get("commands", []),
        "geoip": {
            "country_code": row.get("country_code"),
            "source": row.get("country_source"),
        },
        "network": {
            "asn": row.get("asn"),
            "as_name": row.get("as_name"),
            "bgp_prefix": row.get("bgp_prefix"),
            "asn_source": row.get("asn_source"),
            "rpki_status": row.get("rpki_status"),
            "rpki_source": row.get("rpki_source"),
            "ptr_record": row.get("ptr_record"),
        },
        "threat_intel": {
            "aggregate_verdict": intel.get("aggregate_verdict"),
            "greynoise_classification": intel.get("greynoise_classification"),
            "abuseipdb_score": intel.get("abuseipdb_score"),
            "feodo_listed": intel.get("feodo_listed"),
            "threatfox_listed": intel.get("threatfox_listed"),
            "cached_at": intel.get("cached_at"),
        } if intel else None,
    }


@router.get(
    "/attackers/export",
    tags=["Attacker Profiles"],
    responses={
        200: {"content": {"application/json": {}}, "description": "JSON export download"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.export_attackers")
async def export_attackers(
    user: dict = Depends(require_viewer),
) -> Response:
    """Export all attacker observations and threat-intel as a single JSON file.

    Returns a downloadable JSON blob. Intel columns are null for attackers the
    enrichment worker has not yet processed.
    """
    rows = await repo.get_all_attackers_for_export()
    observations = [_shape_observation(r) for r in rows]
    def _dump(obj: object) -> str:
        return json.dumps(obj, default=str, ensure_ascii=False, separators=(',', ':'))

    meta = _dump({
        "export_metadata": {
            "source": _SOURCE,
            "version": _SCHEMA_VERSION,
            "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "total_records": len(observations),
            "schema_version": _SCHEMA_VERSION,
        }
    })
    obs_lines = ",\n".join(_dump(o) for o in observations)
    content = f'{meta[:-1]},"observations":[\n{obs_lines}\n]}}'
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"decnet-export-{ts}.json"
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
