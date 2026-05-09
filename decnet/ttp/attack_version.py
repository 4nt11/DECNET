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

# MITRE's ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)
# require reproducing their copyright + license alongside any cached
# copy of ATT&CK data. The license file lives at the root of the
# attack-stix-data repository and is fetched into the same cache dir
# as the bundle. ``resolve_bundle_path`` refuses to operate without
# this file present — a hard compliance ratchet, not a soft warning.
ATTACK_LICENSE_URL: Final[str] = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/LICENSE.txt"
)

# sha256 of the LICENSE.txt at the time of pinning. License text gets
# occasional formatting touch-ups, so a mismatch is logged + refreshed
# rather than fail-closed (see _fetch_license in attack_stix.py).
ATTACK_LICENSE_SHA256: Final[str] = (
    "738144f7fb054722a4ef9d3367c51710341dc12fc574c6ac3a41daaaecd8bf5e"
)

ATTACK_LICENSE_FILENAME: Final[str] = "LICENSE.txt"

__all__ = [
    "ATTACK_BUNDLE_SHA256",
    "ATTACK_BUNDLE_URL",
    "ATTACK_BUNDLE_VERSION",
    "ATTACK_LICENSE_FILENAME",
    "ATTACK_LICENSE_SHA256",
    "ATTACK_LICENSE_URL",
]
