"""Canary fingerprint lifter — browser-payload derived technique tagger.

Contract step E.1.6 of ``development/TTP_TAGGING.md``. Empty body.
Implementation phase reads canary-payload fingerprints (navigator
properties, canvas hashes, proxy/VPN leakage signatures) and emits
Discovery / Defense-Evasion techniques. The evidence shape is pinned
to :class:`~decnet.web.db.models.ttp.CanaryFingerprintEvidence`
(``metric`` + ``matched_signature``) — raw fingerprint blobs never
land in evidence.
"""
from __future__ import annotations

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.web.db.models.ttp import TTPTag


class CanaryFingerprintLifter(TolerantTagger):
    name = "canary_fingerprint"
    HANDLES = frozenset({"canary_fingerprint"})

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        return []


__all__ = ["CanaryFingerprintLifter"]
