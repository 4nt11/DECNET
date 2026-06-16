# SPDX-License-Identifier: AGPL-3.0-or-later
"""Contract tests for :mod:`decnet.ttp.factory` (E.1.4).

Scoped to the factory + composite dispatch contract: env var routing,
unknown-name failure, dispatch index correctness, the
KNOWN_SOURCE_KINDS WARNING/INFO bridge for unhandled events.
"""
from __future__ import annotations

import asyncio
import logging

import pytest

from decnet.ttp.base import KNOWN_SOURCE_KINDS, TaggerEvent, TolerantTagger
from decnet.ttp.factory import CompositeTagger, get_tagger
from decnet.web.db.models.ttp import TTPTag


def _ev(source_kind: str) -> TaggerEvent:
    return TaggerEvent(
        source_kind=source_kind,
        source_id="src1",
        attacker_uuid=None,
        identity_uuid="id1",
        session_id=None,
        decky_id=None,
        payload={},
    )


def test_default_returns_composite_with_shipped_lifters(monkeypatch):
    """E.3.9 onward: the default composite is wired with each shipped
    lifter. Empty-lifters was the contract-phase shape; once a lifter
    impl lands the composite carries it.
    """
    monkeypatch.delenv("DECNET_TTP_TAGGER_TYPE", raising=False)
    t = get_tagger()
    assert isinstance(t, CompositeTagger)
    assert t.name == "composite"
    assert len(t._lifters) >= 1


def test_explicit_composite(monkeypatch):
    monkeypatch.setenv("DECNET_TTP_TAGGER_TYPE", "composite")
    assert isinstance(get_tagger(), CompositeTagger)


def test_unknown_tagger_type_raises(monkeypatch):
    monkeypatch.setenv("DECNET_TTP_TAGGER_TYPE", "nope")
    with pytest.raises(ValueError, match="Unknown tagger"):
        get_tagger()


class _Recorder(TolerantTagger):
    """Lifter that records calls and returns a single shaped TTPTag."""

    def __init__(self, name: str, handles: frozenset[str]) -> None:
        self.name = name
        self.HANDLES = handles
        self.calls: list[str] = []

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        self.calls.append(event.source_kind)
        return []


def test_composite_dispatch_index_is_built_from_handles():
    a = _Recorder("a", frozenset({"command", "email"}))
    b = _Recorder("b", frozenset({"email", "intel"}))
    c = CompositeTagger(lifters=[a, b])
    assert set(c._by_kind["command"]) == {a}
    assert set(c._by_kind["email"]) == {a, b}
    assert set(c._by_kind["intel"]) == {b}


def test_composite_only_invokes_claiming_lifters():
    a = _Recorder("a", frozenset({"command"}))
    b = _Recorder("b", frozenset({"email"}))
    c = CompositeTagger(lifters=[a, b])
    asyncio.run(c.tag(_ev("command")))
    assert a.calls == ["command"]
    assert b.calls == []


def test_composite_unhandled_known_kind_logs_warning_once(caplog):
    c = CompositeTagger(lifters=[])
    # Pick any element of KNOWN_SOURCE_KINDS deterministically.
    known = sorted(KNOWN_SOURCE_KINDS)[0]
    caplog.set_level(logging.INFO, logger="decnet.ttp.factory")
    out1 = asyncio.run(c.tag(_ev(known)))
    out2 = asyncio.run(c.tag(_ev(known)))
    assert out1 == [] and out2 == []
    warnings = [
        r for r in caplog.records
        if r.name == "decnet.ttp.factory" and r.levelno == logging.WARNING
    ]
    assert len(warnings) == 1, "expected one WARNING per kind per process"


def test_composite_unhandled_unknown_kind_logs_info_once(caplog):
    c = CompositeTagger(lifters=[])
    unknown = "definitely_not_a_real_source_kind_zzz"
    assert unknown not in KNOWN_SOURCE_KINDS
    caplog.set_level(logging.INFO, logger="decnet.ttp.factory")
    asyncio.run(c.tag(_ev(unknown)))
    asyncio.run(c.tag(_ev(unknown)))
    infos = [
        r for r in caplog.records
        if r.name == "decnet.ttp.factory" and r.levelno == logging.INFO
    ]
    warnings = [
        r for r in caplog.records
        if r.name == "decnet.ttp.factory" and r.levelno == logging.WARNING
    ]
    assert len(infos) == 1
    assert warnings == []


def test_composite_concatenates_results_from_multiple_lifters():
    class Fixed(TolerantTagger):
        def __init__(self, n: int) -> None:
            self.name = f"fixed{n}"
            self.HANDLES = frozenset({"command"})
            self._n = n

        async def _tag_impl(self, event):
            # Return a list of the right length without constructing
            # real TTPTag rows — concatenation semantics are what's
            # under test, not row validity.
            return [object()] * self._n

    c = CompositeTagger(lifters=[Fixed(2), Fixed(3)])
    out = asyncio.run(c.tag(_ev("command")))
    assert len(out) == 5
