# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step F.4: ``environmental.keyboard_layout``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "environmental.keyboard_layout"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed_session(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    """Type ``text`` char-by-char and run as one command."""
    events: list[AsciinemaEvent] = [
        (t0 + i * dt, "i", c) for i, c in enumerate(text)
    ]
    events.append((t0 + len(text) * dt, "i", "\r"))
    return events


def test_below_min_typed_letters_no_emission() -> None:
    out = list(extract_session(_typed_session("hi"), sid="kl-tiny"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_english_text_emits_qwerty() -> None:
    """Pangram repeated to clear LAYOUT_MIN_TYPED_LETTERS (200)."""
    pangram = "the quick brown fox jumps over the lazy dog and then he ran inside the house "
    text = pangram * 5
    obs = _of(list(extract_session(_typed_session(text), sid="kl-en")), PRIMITIVE)
    assert obs.value == "qwerty"


def test_french_with_q_artifacts_emits_azerty() -> None:
    """High `q` rate AND low English saturation → azerty.

    Construct text dominated by `q`-runs and consonant clusters that
    don't form top-10 English bigrams (avoiding `er` / `he` / `th`).
    """
    text = ("qqqqqqq " * 50 + "qsdfg " * 30 + "qpkml " * 30)
    obs = _of(list(extract_session(_typed_session(text), sid="kl-fr")), PRIMITIVE)
    assert obs.value == "azerty"


def test_german_with_z_artifacts_emits_qwertz() -> None:
    """High `z` rate AND low `y` rate → qwertz."""
    # German text simulation: lots of z, almost no y
    text = (
        "zwei zauber zaehlen zwischen zwanzig zelten "
        "zaubern zwanzig zwerge zaehlen zaubern zwanzig "
    ) * 5
    obs = _of(list(extract_session(_typed_session(text), sid="kl-de")), PRIMITIVE)
    assert obs.value == "qwertz"


def test_random_low_signal_emits_other() -> None:
    """Random non-English low-bigram-saturation text → other."""
    # Generate text without English digraphs and without artifact unigrams
    text = ("kpfm vbnj wxlc " * 30)
    obs = _of(list(extract_session(_typed_session(text), sid="kl-other")), PRIMITIVE)
    assert obs.value == "other"


def test_pasted_text_does_not_count() -> None:
    """A long paste shouldn't drive layout — only typed chars count.

    Send everything as a single 'paste-class' input event (>= 4 chars):
    F.4's histograms exclude pastes, so the typed letter count stays
    at zero and emission is skipped.
    """
    pangram = "the quick brown fox jumps over the lazy dog " * 10
    events: list[AsciinemaEvent] = [(0.0, "i", pangram), (1.0, "i", "\r")]
    out = list(extract_session(events, sid="kl-paste"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []
