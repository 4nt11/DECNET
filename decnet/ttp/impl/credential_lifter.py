"""Credential lifter — credential-capture / reuse technique tagger.

Contract step E.1.6 of ``development/TTP_TAGGING.md``. Empty body.
Implementation phase reads ``Credential`` and ``CredentialReuse`` rows
populated by the reuse-correlator and emits Credential-Access /
Lateral-Movement techniques. Tolerates absence of the reuse-correlator
output by inheriting :class:`TolerantTagger` — the correlator is a
sibling worker, not a hard dependency.
"""
from __future__ import annotations

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.web.db.models.ttp import TTPTag


class CredentialLifter(TolerantTagger):
    name = "credential"
    HANDLES = frozenset({"credential"})

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        return []


__all__ = ["CredentialLifter"]
