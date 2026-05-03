"""Step 8: ``cognitive.inter_command_consistency``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _commands_at(starts: list[float]) -> list[AsciinemaEvent]:
    events: list[AsciinemaEvent] = []
    for s in starts:
        events.append((s, "i", "x\r"))
    return events


def test_too_few_iats_no_emission() -> None:
    out = list(extract_session(_commands_at([0.0, 1.0]), sid="cv-low"))
    assert [o for o in out if o.primitive == "cognitive.inter_command_consistency"] == []


def test_uniform_pace_emits_metronomic() -> None:
    # Constant 1s gap → CV 0
    out = list(extract_session(
        _commands_at([i * 1.0 for i in range(8)]), sid="cv-metro",
    ))
    obs = _of(out, "cognitive.inter_command_consistency")
    assert obs.value == "metronomic"


def test_human_like_dispersion_emits_variable() -> None:
    # Pauses around 1s mean with CV ≈ 0.9 (human empirical)
    starts = [0.0, 0.4, 1.4, 1.6, 4.0, 4.4, 7.5]
    out = list(extract_session(_commands_at(starts), sid="cv-var"))
    obs = _of(out, "cognitive.inter_command_consistency")
    assert obs.value == "variable"


def test_extreme_dispersion_emits_bimodal() -> None:
    # Mix of very tight bursts and very long gaps → CV well above 1.5
    starts = [0.0, 0.1, 0.2, 30.0, 30.1, 30.2, 60.0]
    out = list(extract_session(_commands_at(starts), sid="cv-bi"))
    obs = _of(out, "cognitive.inter_command_consistency")
    assert obs.value == "bimodal"


def test_low_sample_count_reduces_confidence() -> None:
    # 3 commands → 2 IATs; below the floor of 5
    short = list(extract_session(_commands_at([0.0, 1.0, 2.0]), sid="cv-short"))
    full = list(extract_session(_commands_at([i * 1.0 for i in range(8)]), sid="cv-full"))
    s = _of(short, "cognitive.inter_command_consistency")
    f = _of(full, "cognitive.inter_command_consistency")
    assert s.confidence < f.confidence
