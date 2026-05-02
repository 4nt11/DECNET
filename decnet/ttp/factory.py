"""Tagger factory + composite tagger.

Contract step E.1.4 of ``development/TTP_TAGGING.md``. Mirrors the
provider-subpackage convention used by :mod:`decnet.intel.factory` and
:mod:`decnet.clustering.factory`: callers obtain the active tagger via
:func:`get_tagger` rather than instantiating a concrete class directly.

The composite tagger is the only shippable tagger type — per-lifter
classes (E.1.6) are children of the composite, not standalone tagger
``DECNET_TTP_TAGGER_TYPE`` values.

Configuration:

* ``DECNET_TTP_TAGGER_TYPE`` — which tagger to instantiate. Default
  ``"composite"``. Unknown values raise :class:`ValueError` so a typo
  in ``decnet.ini`` surfaces immediately rather than silently falling
  back.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Final

from collections.abc import Iterator

from decnet.ttp.base import (
    KNOWN_SOURCE_KINDS,
    Tagger,
    TaggerEvent,
    WatchableTagger,
)
from decnet.web.db.models.ttp import TTPTag

_log = logging.getLogger(__name__)

_KNOWN: Final[tuple[str, ...]] = ("composite",)
_DEFAULT: Final[str] = "composite"


class CompositeTagger(Tagger):
    """Fans an event out to every lifter that claims its ``source_kind``.

    The composite is the runtime end of the closed-by-enumeration
    bridge described in :mod:`decnet.ttp.base`: when an event arrives
    with a ``source_kind`` no lifter claims, the composite emits a
    structured log line so the silent-drop trap from the design doc
    becomes observable.

    During the contract phase (this commit) ``lifters=[]`` is the
    legal state — E.1.6 wires the real per-source lifters in.
    """

    name = "composite"
    # The composite itself accepts every event; per-kind dispatch is
    # delegated to children. Empty here is "n/a, computed from
    # children" — the dispatch index below is what actually drives
    # the fan-out.
    HANDLES: frozenset[str] = frozenset()

    def __init__(self, lifters: list[Tagger]) -> None:
        self._lifters: list[Tagger] = list(lifters)
        index: dict[str, list[Tagger]] = {}
        for lifter in self._lifters:
            for kind in lifter.HANDLES:
                index.setdefault(kind, []).append(lifter)
        self._by_kind: dict[str, list[Tagger]] = index
        # Per-process dedup state so a flood of one unknown kind
        # produces one log line, not one per event. A simple set
        # is fine for the contract; E.1.6 may swap in a proper
        # rate-limiter once production traffic shapes are known.
        self._warned_known: set[str] = set()
        self._informed_unknown: set[str] = set()

    def iter_watchables(self) -> Iterator[WatchableTagger]:
        """Yield every child lifter that hot-reloads from a RuleStore.

        The worker (E.3.14) starts one ``asyncio.Task`` per yielded
        lifter so its dispatch index hydrates at startup; without this
        every index stays empty and no rule fires in production.
        Filtering on the structural :class:`WatchableTagger` protocol
        keeps the worker free of per-lifter type knowledge.
        """
        for lifter in self._lifters:
            if isinstance(lifter, WatchableTagger):
                yield lifter

    async def tag(self, event: TaggerEvent) -> list[TTPTag]:
        lifters = self._by_kind.get(event.source_kind, [])
        if not lifters:
            self._log_unhandled(event.source_kind)
            return []
        results = await asyncio.gather(*(t.tag(event) for t in lifters))
        out: list[TTPTag] = []
        for tags in results:
            out.extend(tags)
        return out

    def _log_unhandled(self, source_kind: str) -> None:
        if source_kind in KNOWN_SOURCE_KINDS:
            if source_kind not in self._warned_known:
                self._warned_known.add(source_kind)
                # Producer ships a kind that *should* be handled but
                # no lifter claims it — almost certainly a missed
                # E.1.6 update. Loud once per kind per process.
                _log.warning(
                    "composite tagger: no lifter claims known "
                    "source_kind=%r; events will be dropped until a "
                    "lifter is registered",
                    source_kind,
                )
        else:
            if source_kind not in self._informed_unknown:
                self._informed_unknown.add(source_kind)
                # Telemetry from a future feature, no lifter yet, by
                # design (lines 160–195 of the design doc). INFO once
                # per process; never an error.
                _log.info(
                    "composite tagger: unknown source_kind=%r "
                    "(not in KNOWN_SOURCE_KINDS); ignoring",
                    source_kind,
                )


def get_tagger() -> Tagger:
    """Return the configured tagger instance.

    Synchronous construction: each shipped lifter takes the shared
    :class:`RuleStore` reference, but the per-lifter watch loops are
    started by the worker (E.3.14), not by this factory. Tests that
    instantiate via this path get an idle composite — exercising the
    watch loop is the worker's contract.
    """
    name = os.environ.get("DECNET_TTP_TAGGER_TYPE", _DEFAULT).strip().lower()
    if name == "composite":
        from decnet.ttp.impl.behavioral_lifter import BehavioralLifter
        from decnet.ttp.impl.canary_fingerprint_lifter import (
            CanaryFingerprintLifter,
        )
        from decnet.ttp.impl.credential_lifter import CredentialLifter
        from decnet.ttp.impl.email_lifter import EmailLifter
        from decnet.ttp.impl.identity_lifter import IdentityLifter
        from decnet.ttp.impl.intel_lifter import IntelLifter
        from decnet.ttp.impl.rule_engine import RuleEngineTagger
        from decnet.ttp.store.factory import get_rule_store
        store = get_rule_store()
        # RuleEngineTagger first so generic pattern rules dispatch
        # before the per-source lifters' cross-event logic. Order is
        # observational — every tagger sees every event for its
        # `HANDLES` set; tags from all of them aggregate into a single
        # `ttp.tagged` envelope at the worker.
        return CompositeTagger(lifters=[
            RuleEngineTagger(store),
            BehavioralLifter(store),
            IntelLifter(store),
            CanaryFingerprintLifter(store),
            EmailLifter(store),
            IdentityLifter(store),
            CredentialLifter(store),
        ])
    raise ValueError(
        f"Unknown tagger: {name!r}. Known: {_KNOWN}"
    )


__all__ = ["get_tagger", "CompositeTagger"]
