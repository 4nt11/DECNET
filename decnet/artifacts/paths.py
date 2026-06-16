"""
Shared on-disk artifact path resolution.

Honeypot decoys (SSH, SMTP) farm captured payloads into a host-mounted
quarantine tree:

    /var/lib/decnet/artifacts/{decky}/{service}/{stored_as}

Two callers need to translate ``(decky, stored_as, service)`` into a
concrete ``Path`` rooted under that tree:

* The web router endpoint ``GET /api/v1/artifacts/{decky}/{stored_as}``
  (``decnet.web.router.artifacts.api_get_artifact``) — admin-gated
  download for the dashboard.
* The TTP ``EmailLifter`` (``decnet.ttp.impl.email_lifter``), which
  reads the stored ``.eml`` at tag-time so body-aware predicates
  (R0047 BEC, R0048 macro) don't need raw body text on the bus.

Both callers share the same validation rules and the same
defence-in-depth symlink-escape check; this module is the single
implementation. It is auth-agnostic — wrappers layer authentication
where appropriate (the router does ``require_admin``, the lifter does
not).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# decky names come from the deployer — lowercase alnum plus hyphens.
_DECKY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

# Services that own an artifacts subdir. Kept explicit so a caller
# can't pivot into arbitrary subpaths via a query string or bus payload.
_ALLOWED_SERVICES = frozenset({"ssh", "smtp"})

# stored_as is assembled by the capturing template as:
#   ${ts}_${sha:0:12}_${base}
# where ts is ISO-8601 UTC (e.g. 2026-04-18T02:22:56Z), sha is 12 hex chars,
# and base is the original filename's basename. Keep the filename charset
# tight but allow common punctuation dropped files actually use.
_STORED_AS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z_[a-f0-9]{12}_[A-Za-z0-9._-]{1,255}$"
)

# Module-level so tests can monkeypatch. Override via env in production
# (the systemd unit sets this) — the prod path matches the bind mount
# declared in decnet/services/{ssh,smtp}.py.
ARTIFACTS_ROOT = Path(
    os.environ.get("DECNET_ARTIFACTS_ROOT", "/var/lib/decnet/artifacts")
)


class ArtifactPathError(ValueError):
    """Raised when (decky, stored_as, service) fails validation or escapes
    the artifacts root.

    The router catches this and re-raises HTTPException(400). The lifter
    catches it and treats the event as having no body available (no-tag).
    """


def resolve_artifact_path(decky: str, stored_as: str, service: str) -> Path:
    """Validate inputs, resolve the on-disk path, and confirm it stays
    inside the artifacts root.

    Raises :class:`ArtifactPathError` on any violation. Does NOT check
    that the file exists — callers handle that distinctly (404 for the
    router, no-tag for the lifter).
    """
    if service not in _ALLOWED_SERVICES:
        raise ArtifactPathError("invalid service")
    if not _DECKY_RE.fullmatch(decky):
        raise ArtifactPathError("invalid decky name")
    if not _STORED_AS_RE.fullmatch(stored_as):
        raise ArtifactPathError("invalid stored_as")

    root = ARTIFACTS_ROOT.resolve()
    candidate = (root / decky / service / stored_as).resolve()
    # defence-in-depth: even though the regexes reject `..`, make sure a
    # symlink or weird filesystem state can't escape the root.
    if root not in candidate.parents and candidate != root:
        raise ArtifactPathError("path escapes artifacts root")
    return candidate
