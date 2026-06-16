# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step G.5: ``emotional_valence.valence`` ∈ {positive, neutral, negative}.

Hard 0.5 confidence cap.
"""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "emotional_valence.valence"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def test_too_little_text_no_emission() -> None:
    out = list(extract_session(_typed("hi"), sid="g5-thin"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_positive_valence() -> None:
    text = (
        "thanks great nice perfect awesome love thanks great nice perfect "
        "this is going perfectly well today thanks "
    )
    obs = _of(list(extract_session(_typed(text), sid="g5-pos")), PRIMITIVE)
    assert obs.value == "positive"
    assert obs.confidence <= 0.50


def test_negative_valence_via_obscenity_and_negatives() -> None:
    text = (
        "fuck this is broken damn it stuck here wtf fuck shit "
        "everything is broken and stupid today again broken again "
        "wrong wrong wrong total disaster here and now "
    )
    obs = _of(list(extract_session(_typed(text), sid="g5-neg")), PRIMITIVE)
    assert obs.value == "negative"
    assert obs.confidence <= 0.50


def test_neutral_valence_when_no_lexicon_hits() -> None:
    text = (
        "running command for inspection of remote system today "
        "checking files and verifying things look correct overall "
    )
    obs = _of(list(extract_session(_typed(text), sid="g5-neutral")), PRIMITIVE)
    assert obs.value == "neutral"


def test_confidence_hard_capped_at_05() -> None:
    text = "thanks " * 50  # plenty positive, plenty long
    obs = _of(list(extract_session(_typed(text), sid="g5-cap")), PRIMITIVE)
    assert obs.confidence <= 0.50


def test_low_text_count_lower_confidence() -> None:
    text = "thanks great nice perfect awesome love " * 3
    obs = _of(list(extract_session(_typed(text), sid="g5-lowconf")), PRIMITIVE)
    assert obs.confidence == 0.30
