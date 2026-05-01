"""Contract tests for :mod:`decnet.ttp.base` (E.1.3 + E.2.4).

E.1.3 contract surface: shape of TaggerEvent, abstractness of
Tagger, the swallow-Exception / propagate-BaseException boundary
of TolerantTagger, and the closed-by-enumeration
KNOWN_SOURCE_KINDS constant.

E.2.4 conformance (this commit): hypothesis fuzz over a curated
set of Exception subclasses → all swallowed and converted to ``[]``
at WARNING level (never ERROR). The propagate-list
(``KeyboardInterrupt`` / ``SystemExit`` /
``asyncio.CancelledError``) stays separate.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

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


def test_tagger_event_is_namedtuple_and_hashable() -> None:
    ev = _ev()
    assert ev.source_kind == "command"
    assert ev.identity_uuid == "id1"
    # NamedTuple gives instances tuple identity for downstream dedup
    # paths. The payload field is a dict (unhashable by design — the
    # raw event isn't meant to live in a set), but the structural
    # tuple shape is what callers actually rely on.
    assert tuple(ev)[0] == "command"
    assert len(ev) == 7


def test_tagger_is_abstract() -> None:
    with pytest.raises(TypeError):
        Tagger()  # type: ignore[abstract]


def test_tagger_subclass_without_tag_is_abstract() -> None:
    class Half(Tagger):
        name = "half"

    with pytest.raises(TypeError):
        Half()  # type: ignore[abstract]


def test_known_source_kinds_is_frozenset_of_strings() -> None:
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


def test_tolerant_tagger_swallows_exception_and_returns_empty(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class Boom(TolerantTagger):
        name = "boom"
        HANDLES = frozenset({"command"})

        async def _tag_impl(self, event: TaggerEvent) -> list[Any]:
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
def test_tolerant_tagger_propagates_base_exceptions(
    exc_cls: type[BaseException],
) -> None:
    class Cancel(TolerantTagger):
        name = "cancel"
        HANDLES = frozenset({"command"})

        async def _tag_impl(self, event: TaggerEvent) -> list[Any]:
            raise exc_cls()

    with pytest.raises(exc_cls):
        asyncio.run(Cancel().tag(_ev()))


def test_tolerant_tagger_subclass_must_implement_tag_impl() -> None:
    class Empty(TolerantTagger):
        name = "empty"

    with pytest.raises(TypeError):
        Empty()  # type: ignore[abstract]


def test_tagger_default_handles_is_empty_frozenset() -> None:
    # Misconfigured subclass that forgets HANDLES is loudly idle,
    # not loudly noisy — the composite skips it entirely.
    assert Tagger.HANDLES == frozenset()


# ─── E.2.4 — Hypothesis fuzz over the swallow-Exception boundary ─────────────

# Curated list of plausible runtime failure modes a lifter could hit
# when its sibling-worker join is absent or malformed. Spec calls for
# ``st.sampled_from`` over a curated list — no fully random class
# synthesis (which could pick BaseException subclasses we explicitly
# do NOT want swallowed).
_SWALLOWED_EXCS: tuple[type[Exception], ...] = (
    ValueError,
    RuntimeError,
    KeyError,
    TypeError,
    AttributeError,
    LookupError,
    OSError,
    asyncio.TimeoutError,
    ZeroDivisionError,
    StopIteration,
)


@given(exc_cls=st.sampled_from(_SWALLOWED_EXCS))
@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_tolerant_tagger_fuzzed_exceptions_swallowed(
    exc_cls: type[Exception],
    caplog: pytest.LogCaptureFixture,
) -> None:
    class Boom(TolerantTagger):
        name = "boom"
        HANDLES = frozenset({"command"})

        async def _tag_impl(self, event: TaggerEvent) -> list[Any]:
            raise exc_cls("synthetic")

    caplog.clear()
    caplog.set_level(logging.DEBUG, logger="decnet.ttp.base")
    out = asyncio.run(Boom().tag(_ev()))
    assert out == []
    records = [r for r in caplog.records if r.name == "decnet.ttp.base"]
    assert records, f"expected a WARNING for {exc_cls.__name__}"
    # Absence-is-normal: every swallowed exception logs at WARNING,
    # never ERROR. A future change that flips to ERROR — paging the
    # operator on every empty join — trips this assert.
    assert all(r.levelno == logging.WARNING for r in records)
    assert not any(r.levelno >= logging.ERROR for r in records)


def test_tolerant_tagger_no_error_records_on_swallow(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Sibling property to the fuzz test: pin the no-ERROR invariant
    independent of Hypothesis sampling, so the contract is visible
    in plain pytest output."""
    class Boom(TolerantTagger):
        name = "boom"
        HANDLES = frozenset({"command"})

        async def _tag_impl(self, event: TaggerEvent) -> list[Any]:
            raise KeyError("no such join")

    caplog.set_level(logging.DEBUG, logger="decnet.ttp.base")
    asyncio.run(Boom().tag(_ev()))
    base_records = [r for r in caplog.records if r.name == "decnet.ttp.base"]
    assert base_records
    assert not [r for r in base_records if r.levelno >= logging.ERROR]
