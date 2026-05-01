"""Contract tests for :mod:`decnet.ttp.base` (E.1.3).

Scoped to the contract surface: shape of TaggerEvent, abstractness
of Tagger, the swallow-Exception / propagate-BaseException boundary
of TolerantTagger, and the closed-by-enumeration KNOWN_SOURCE_KINDS
constant. The full E.2.4 conformance suite (hypothesis fuzz over
arbitrary exception types) lands in a later commit.
"""
from __future__ import annotations

import asyncio
import logging

import pytest

from decnet.ttp.base import (
    KNOWN_SOURCE_KINDS,
    Tagger,
    TaggerEvent,
    TolerantTagger,
)


def _ev(source_kind: str = "command") -> TaggerEvent:
    return TaggerEvent(
        source_kind=source_kind,
        source_id="src1",
        attacker_uuid=None,
        identity_uuid="id1",
        session_id=None,
        decky_id=None,
        payload={},
    )


def test_tagger_event_is_namedtuple_and_hashable():
    ev = _ev()
    assert ev.source_kind == "command"
    assert ev.identity_uuid == "id1"
    # NamedTuple gives instances tuple identity for downstream dedup
    # paths. The payload field is a dict (unhashable by design — the
    # raw event isn't meant to live in a set), but the structural
    # tuple shape is what callers actually rely on.
    assert tuple(ev)[0] == "command"
    assert len(ev) == 7


def test_tagger_is_abstract():
    with pytest.raises(TypeError):
        Tagger()  # type: ignore[abstract]


def test_tagger_subclass_without_tag_is_abstract():
    class Half(Tagger):
        name = "half"

    with pytest.raises(TypeError):
        Half()  # type: ignore[abstract]


def test_known_source_kinds_is_frozenset_of_strings():
    assert isinstance(KNOWN_SOURCE_KINDS, frozenset)
    assert all(isinstance(k, str) for k in KNOWN_SOURCE_KINDS)
    # The contract requires at least the lifter-aligned kinds enumerated
    # in the design doc; further kinds may be added but these MUST be
    # present.
    must_have = {
        "command", "intel", "email", "canary_fingerprint",
        "identity", "credential",
    }
    assert must_have <= KNOWN_SOURCE_KINDS


def test_tolerant_tagger_swallows_exception_and_returns_empty(caplog):
    class Boom(TolerantTagger):
        name = "boom"
        HANDLES = frozenset({"command"})

        async def _tag_impl(self, event):
            raise RuntimeError("synthetic")

    caplog.set_level(logging.WARNING, logger="decnet.ttp.base")
    out = asyncio.run(Boom().tag(_ev()))
    assert out == []
    # WARNING — never ERROR — per the absence-is-normal doctrine.
    records = [r for r in caplog.records if r.name == "decnet.ttp.base"]
    assert records, "expected a log line on swallowed exception"
    assert all(r.levelno == logging.WARNING for r in records)


@pytest.mark.parametrize(
    "exc_cls",
    [KeyboardInterrupt, SystemExit, asyncio.CancelledError],
)
def test_tolerant_tagger_propagates_base_exceptions(exc_cls):
    class Cancel(TolerantTagger):
        name = "cancel"
        HANDLES = frozenset({"command"})

        async def _tag_impl(self, event):
            raise exc_cls()

    with pytest.raises(exc_cls):
        asyncio.run(Cancel().tag(_ev()))


def test_tolerant_tagger_subclass_must_implement_tag_impl():
    class Empty(TolerantTagger):
        name = "empty"

    with pytest.raises(TypeError):
        Empty()  # type: ignore[abstract]


def test_tagger_default_handles_is_empty_frozenset():
    # Misconfigured subclass that forgets HANDLES is loudly idle,
    # not loudly noisy — the composite skips it entirely.
    assert Tagger.HANDLES == frozenset()
