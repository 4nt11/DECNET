"""Tagger ABC — input shape, base class, tolerant mixin.

Contract step E.1.3 of ``development/TTP_TAGGING.md``. Defines the type
surface every lifter (E.1.6), the rule engine (E.1.5), the composite
tagger (E.1.4) and the worker (E.1.7) compile against. No behavior
beyond the tolerant-wrapper boundary lives here.

The design doc's "schema is forward-compat, code is not" trap (lines
160–195) is mitigated *here*: :data:`KNOWN_SOURCE_KINDS` enumerates
every ``source_kind`` a producer is allowed to emit. Adding a new
producer means adding its kind to this set in the *same commit* that
ships the producer; the composite tagger's WARNING/INFO bridge in
:mod:`decnet.ttp.factory` keys off this constant to surface silent
drops.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Final, NamedTuple, Protocol, runtime_checkable

from decnet.web.db.models.ttp import TTPTag

_log = logging.getLogger(__name__)


# Every ``source_kind`` string a DECNET producer is allowed to emit.
# Closed-by-enumeration at the runtime layer even though the storage
# column is open. Producers MUST add their kind here in the same
# commit that starts emitting — see the design doc lines 160–195 for
# the operational contract and the rationale.
KNOWN_SOURCE_KINDS: Final[frozenset[str]] = frozenset({
    "command",
    "intel",
    "email",
    "canary_fingerprint",
    "identity",
    "credential",
    "auth_attempt",
    "payload",
    "session",
    "http_request",
})


class TaggerEvent(NamedTuple):
    """Input shape for every tagger.

    NamedTuple (not dataclass) so instances are hashable — downstream
    dedup paths can put them in sets without a custom ``__hash__``.
    ``payload`` is opaque on purpose: each ``source_kind`` carries a
    different shape, and the per-lifter contract owns the parse.
    """

    source_kind: str
    source_id: str
    attacker_uuid: str | None
    identity_uuid: str | None
    session_id: str | None
    decky_id: str | None
    payload: dict[str, Any]


class Tagger(ABC):
    """Abstract tagger.

    Every concrete tagger sets :attr:`name` and :attr:`HANDLES` at
    class level. The composite tagger reads ``HANDLES`` to build its
    dispatch index — a subclass that forgets to override it gets the
    empty default and is therefore never invoked, which surfaces as a
    test failure rather than a silent fan-out.
    """

    #: Short tag used in logs and the ``DECNET_TTP_TAGGER_TYPE`` env
    #: var. Subclasses override.
    name: str = ""

    #: ``source_kind`` strings this tagger consumes. Empty by default
    #: so a misconfigured subclass is loudly idle, not loudly noisy.
    HANDLES: frozenset[str] = frozenset()

    @abstractmethod
    async def tag(self, event: TaggerEvent) -> list[TTPTag]:
        """Produce zero or more tags for ``event``.

        Implementations of :class:`Tagger` directly take responsibility
        for their own error handling. Lifters that consume
        sibling-worker output inherit from :class:`TolerantTagger`
        instead, which enforces the "absence is not an error" contract
        in the base class rather than on trust.
        """


class TolerantTagger(Tagger):
    """Tagger mixin that converts uncaught exceptions to ``[]``.

    Every per-source lifter inherits from this. The rationale is
    architectural, not stylistic: TTP tagging consumes outputs from
    sibling workers (intel, behavioral, identity, …) that may not
    have run yet, may have failed, or may simply have nothing to say
    about a given event. "Absence" is the steady state, not the
    exception, so a lifter blowing up on a missing join must not
    cascade into a worker crash.

    Subclasses override :meth:`_tag_impl`, never :meth:`tag` — the
    tolerance contract is *enforced in the base class*, not on trust.
    """

    async def tag(self, event: TaggerEvent) -> list[TTPTag]:
        try:
            return await self._tag_impl(event)
        except Exception:
            # ``Exception`` deliberately, not ``BaseException``:
            # ``KeyboardInterrupt`` / ``SystemExit`` /
            # ``asyncio.CancelledError`` propagate so the worker can
            # shut down cleanly. E.2.4 conformance asserts this.
            # WARNING, not ERROR: a sibling-worker absence is normal
            # operation, not a bug. ERROR would page someone for the
            # steady state.
            _log.warning(
                "tagger %r swallowed exception on source_kind=%r",
                self.name,
                event.source_kind,
                exc_info=True,
            )
            return []

    @abstractmethod
    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        """Real tagging logic — subclasses override this, not :meth:`tag`."""


@runtime_checkable
class WatchableTagger(Protocol):
    """Structural protocol for taggers that hot-reload from a RuleStore.

    Each per-source lifter (and :class:`RuleEngineTagger`) holds its
    own :class:`~decnet.ttp.impl._rule_index.RuleIndex` and exposes an
    ``async def watch_store()`` coroutine that loads the initial
    corpus and drains store change events forever. The worker
    (E.3.14) starts one task per ``WatchableTagger`` so dispatch
    indexes hydrate at startup; without this the indexes stay empty
    and no rule fires. ``runtime_checkable`` so the worker can fan
    out via :func:`isinstance` without leaking the protocol into the
    abstract :class:`Tagger` base.
    """

    async def watch_store(self) -> None: ...


__all__ = [
    "KNOWN_SOURCE_KINDS",
    "TaggerEvent",
    "Tagger",
    "TolerantTagger",
    "WatchableTagger",
]
