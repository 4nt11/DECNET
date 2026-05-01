"""Identity lifter — cross-attacker identity-rollup tagger.

Contract step E.1.6 of ``development/TTP_TAGGING.md``. Empty body.
Implementation phase reads identity-formation events (the clusterer
publishing ``identity.formed``) and emits techniques that are only
visible at the identity scope, never per-attacker — for example,
infrastructure rotation or credential reuse across IPs that were
clustered into one identity. Tags carry ``identity_uuid`` and a NULL
``attacker_uuid`` per the design doc's "identity rollup" worked
example.
"""
from __future__ import annotations

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.web.db.models.ttp import TTPTag


class IdentityLifter(TolerantTagger):
    name = "identity"
    HANDLES = frozenset({"identity"})

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        return []


__all__ = ["IdentityLifter"]
