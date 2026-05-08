"""Step G.8: ``emotional_valence.frustration_venting`` ∈ {none, detected}.

Hard 0.5 confidence cap.
"""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "emotional_valence.frustration_venting"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def test_too_little_text_no_emission() -> None:
    out = list(extract_session(_typed("hi"), sid="g8-thin"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_detected_when_obscenity_present() -> None:
    text = "hostname date hostname date oh fuck this is broken really "
    obs = _of(list(extract_session(_typed(text), sid="g8-yes")), PRIMITIVE)
    assert obs.value == "detected"
    assert obs.confidence == 0.40


def test_none_when_clean() -> None:
    text = "hostname date hostname date hostname date hostname date "
    obs = _of(list(extract_session(_typed(text), sid="g8-no")), PRIMITIVE)
    assert obs.value == "none"


def test_high_confidence_when_long_clean() -> None:
    text = "hostname date " * 30
    obs = _of(list(extract_session(_typed(text), sid="g8-long")), PRIMITIVE)
    assert obs.value == "none"
    assert obs.confidence == 0.50


def test_cap_never_exceeded() -> None:
    text = "fuck shit damn " * 30
    obs = _of(list(extract_session(_typed(text), sid="g8-cap")), PRIMITIVE)
    assert obs.confidence <= 0.50
