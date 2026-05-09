"""Pinned MITRE ATT&CK Enterprise STIX bundle version.

Bumping ``ATTACK_BUNDLE_VERSION`` is the *only* code change required
to track a new ATT&CK release — all technique/tactic names and
sub-technique parents are loaded from the bundle at runtime via
``decnet.ttp.attack_stix``. The hash is verified after fetch; a
mismatch refuses to load (fail-closed, mirroring the bundle-include
discipline used elsewhere in DECNET).

To regenerate the hash after a version bump::

    .311/bin/python -m decnet.ttp.attack_stix fetch --print-sha
"""
from __future__ import annotations

from typing import Final

ATTACK_BUNDLE_VERSION: Final[str] = "19.0"

# sha256 of the canonical MITRE-published enterprise-attack-19.0.json
# from https://github.com/mitre-attack/attack-stix-data.
ATTACK_BUNDLE_SHA256: Final[str] = (
    "df520ea0775a57db7bff760145b02fed89290802913e056b7ed5970b02f3626a"
)

# Raw download URL for the pinned version.
ATTACK_BUNDLE_URL: Final[str] = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    f"/master/enterprise-attack/enterprise-attack-{ATTACK_BUNDLE_VERSION}.json"
)

__all__ = [
    "ATTACK_BUNDLE_SHA256",
    "ATTACK_BUNDLE_URL",
    "ATTACK_BUNDLE_VERSION",
]
