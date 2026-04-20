"""
Artifact download endpoint.

SSH deckies farm attacker file drops into a host-mounted quarantine:
  /var/lib/decnet/artifacts/{decky}/ssh/{stored_as}

The capture event already flows through the normal log pipeline (one
RFC 5424 line per capture, see templates/ssh/emit_capture.py), so metadata
is served via /logs. This endpoint exists only to retrieve the raw bytes —
admin-gated because the payloads are attacker-controlled content.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_admin

router = APIRouter()

# Override via env for tests; the prod path matches the bind mount declared in
# decnet/services/ssh.py.
ARTIFACTS_ROOT = Path(os.environ.get("DECNET_ARTIFACTS_ROOT", "/var/lib/decnet/artifacts"))

# decky names come from the deployer — lowercase alnum plus hyphens.
_DECKY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

# stored_as is assembled by capture.sh as:
#   ${ts}_${sha:0:12}_${base}
# where ts is ISO-8601 UTC (e.g. 2026-04-18T02:22:56Z), sha is 12 hex chars,
# and base is the original filename's basename. Keep the filename charset
# tight but allow common punctuation dropped files actually use.
_STORED_AS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z_[a-f0-9]{12}_[A-Za-z0-9._-]{1,255}$"
)


def _resolve_artifact_path(decky: str, stored_as: str) -> Path:
    """Validate inputs, resolve the on-disk path, and confirm it stays inside
    the artifacts root. Raises HTTPException(400) on any violation."""
    if not _DECKY_RE.fullmatch(decky):
        raise HTTPException(status_code=400, detail="invalid decky name")
    if not _STORED_AS_RE.fullmatch(stored_as):
        raise HTTPException(status_code=400, detail="invalid stored_as")

    root = ARTIFACTS_ROOT.resolve()
    candidate = (root / decky / "ssh" / stored_as).resolve()
    # defence-in-depth: even though the regexes reject `..`, make sure a
    # symlink or weird filesystem state can't escape the root.
    if root not in candidate.parents and candidate != root:
        raise HTTPException(status_code=400, detail="path escapes artifacts root")
    return candidate


@router.get(
    "/artifacts/{decky}/{stored_as}",
    tags=["Artifacts"],
    responses={
        400: {"description": "Invalid decky or stored_as parameter"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required"},
        404: {"description": "Artifact not found"},
    },
)
@_traced("api.get_artifact")
async def get_artifact(
    decky: str,
    stored_as: str,
    admin: dict = Depends(require_admin),
) -> FileResponse:
    path = _resolve_artifact_path(decky, stored_as)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="artifact not found")
    return FileResponse(
        path=str(path),
        media_type="application/octet-stream",
        filename=stored_as,
    )
