"""Intel lifter — opportunistic third-party verdict translator.

Contract step E.1.6 of ``development/TTP_TAGGING.md``. Empty body.
Implementation phase reads ``AttackerIntel`` rows and translates
provider verdicts (AbuseIPDB categories, GreyNoise classification,
Feodo / ThreatFox membership) into ATT&CK technique tags with
confidence scaled by per-provider reliability.

The decoupling rule (design doc §"Decoupling: bus-driven, never a
hard dependency") is enforced statically by E.2.7: this module MUST
NOT import from ``decnet.intel.{abuseipdb,greynoise,feodo,threatfox}``.
Only ``decnet.web.db.models`` symbols are permitted.
"""
from __future__ import annotations

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.web.db.models.ttp import TTPTag


class IntelLifter(TolerantTagger):
    name = "intel"
    #: ``intel`` events are bus-published when an ``AttackerIntel`` row
    #: is upserted; the lifter treats absence as the steady state.
    HANDLES = frozenset({"intel"})

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        return []


__all__ = ["IntelLifter"]
