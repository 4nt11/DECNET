# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step G.6: ``emotional_valence.arousal`` ∈ {low_calm, medium_engaged,
high_agitated}.

Hard 0.5 confidence cap.
"""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "emotional_valence.arousal"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def test_no_typing_bursts_no_emission() -> None:
    out = list(extract_session([(0.0, "i", "x")], sid="g6-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_high_agitated_via_caps_run() -> None:
    """Long capslock streak fires high_agitated regardless of pace."""
    text = "ls\rWHAT IS GOING ON HERE\rls\r"
    obs = _of(list(extract_session(_typed(text), sid="g6-caps")), PRIMITIVE)
    assert obs.value == "high_agitated"
    assert obs.confidence <= 0.50


def test_high_agitated_via_bangs() -> None:
    text = "ls\rno!!!! something\rls\r"
    obs = _of(list(extract_session(_typed(text), sid="g6-bang")), PRIMITIVE)
    assert obs.value == "high_agitated"


def test_high_agitated_via_fast_typing() -> None:
    """Long fast burst (dt=0.04) fires high_agitated."""
    text = "thequickbrownfoxjumpsoverthelazydog" * 2
    obs = _of(
        list(extract_session(_typed(text, dt=0.04), sid="g6-fast")), PRIMITIVE
    )
    assert obs.value == "high_agitated"


def test_low_calm_slow_typing() -> None:
    """Long slow burst (dt=0.40) fires low_calm."""
    text = "thequickbrownfoxjumpsoverthelazydog" * 2
    obs = _of(
        list(extract_session(_typed(text, dt=0.40), sid="g6-calm")), PRIMITIVE
    )
    assert obs.value == "low_calm"


def test_confidence_capped_at_05() -> None:
    text = "thequickbrownfoxjumpsoverthelazydog" * 2
    obs = _of(
        list(extract_session(_typed(text, dt=0.10), sid="g6-cap")), PRIMITIVE
    )
    assert obs.confidence <= 0.50
