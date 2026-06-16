# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step E.1: ``temporal.session_duration``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "temporal.session_duration"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def test_empty_session_no_emission() -> None:
    out = list(extract_session([], sid="dur-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_under_60s_emits_short() -> None:
    events: list[AsciinemaEvent] = [(0.0, "i", "a"), (30.0, "i", "b")]
    obs = _of(list(extract_session(events, sid="dur-short")), PRIMITIVE)
    assert obs.value == "short"


def test_under_600s_emits_medium() -> None:
    events: list[AsciinemaEvent] = [(0.0, "i", "a"), (300.0, "i", "b")]
    obs = _of(list(extract_session(events, sid="dur-med")), PRIMITIVE)
    assert obs.value == "medium"


def test_under_3600s_emits_long() -> None:
    events: list[AsciinemaEvent] = [(0.0, "i", "a"), (1800.0, "i", "b")]
    obs = _of(list(extract_session(events, sid="dur-long")), PRIMITIVE)
    assert obs.value == "long"


def test_over_3600s_emits_marathon() -> None:
    events: list[AsciinemaEvent] = [(0.0, "i", "a"), (7200.0, "i", "b")]
    obs = _of(list(extract_session(events, sid="dur-marathon")), PRIMITIVE)
    assert obs.value == "marathon"


def test_high_confidence() -> None:
    """Duration is a fact, not an inference — confidence stays high."""
    events: list[AsciinemaEvent] = [(0.0, "i", "a"), (30.0, "i", "b")]
    obs = _of(list(extract_session(events, sid="dur-conf")), PRIMITIVE)
    assert obs.confidence >= 0.80
