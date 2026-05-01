"""Behavioral lifter — derives techniques from cross-event session signal.

Contract step E.1.6 of ``development/TTP_TAGGING.md``. Empty body.
Implementation phase reads ``AttackerBehavior`` rows assembled by the
profiler and emits techniques the rule engine cannot see (timing,
ordering, command-graph shape). Inherits :class:`TolerantTagger` so a
missing ``AttackerBehavior`` join silently returns ``[]`` — sibling
worker absence is the steady state, not an error.
"""
from __future__ import annotations

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.web.db.models.ttp import TTPTag


class BehavioralLifter(TolerantTagger):
    name = "behavioral"
    #: Session-level events triggering a behavior-graph lookup. The
    #: lifter reads ``AttackerBehavior`` keyed on the session.
    HANDLES = frozenset({"session"})

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        return []


__all__ = ["BehavioralLifter"]
