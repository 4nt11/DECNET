# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step D.1: ``cognitive.cognitive_load``.

Composite of three [0, 1]-clipped sub-signals (chunking variance, error
rate, pace variability) → bucketed against COGNITIVE_LOAD_LOW_MAX /
COGNITIVE_LOAD_MEDIUM_MAX. Tests pin each component at its extremes and
confirm the bucket falls where the math says.
"""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def _metronomic_clean_session(n: int = 8) -> list[AsciinemaEvent]:
    """``n`` commands, perfectly even pacing, zero errors, fluent typing."""
    events: list[AsciinemaEvent] = []
    for i in range(n):
        events.extend(_typed("ls\r", t0=i * 1.0, dt=0.05))
    return events


def test_no_commands_no_emission() -> None:
    events: list[AsciinemaEvent] = [(0.0, "i", "a")]
    out = list(extract_session(events, sid="cl-empty"))
    assert [o for o in out if o.primitive == "cognitive.cognitive_load"] == []


def test_metronomic_clean_session_emits_low() -> None:
    """Even pacing + clean output + steady typing → low load."""
    out = list(extract_session(_metronomic_clean_session(8), sid="cl-low"))
    obs = _of(out, "cognitive.cognitive_load")
    assert obs.value == "low"


def test_high_error_rate_drives_load_up() -> None:
    """Every command errored — error_load = 1.0 alone forces load >= 0.33."""
    events: list[AsciinemaEvent] = []
    for i in range(8):
        events.extend(_typed("foo\r", t0=i * 1.0, dt=0.05))
        events.append((i * 1.0 + 0.5, "o", "bash: foo: command not found\n"))
    out = list(extract_session(events, sid="cl-err"))
    obs = _of(out, "cognitive.cognitive_load")
    assert obs.value in ("medium", "high")


def test_all_three_components_high_emits_high() -> None:
    """Saturate every component → load ≈ 1.0 → high."""
    events: list[AsciinemaEvent] = []
    # Burst-then-gap pacing maximises pace-CV; mid-command jitter
    # maximises chunking-CV; every command errors.
    starts = [0.0, 0.1, 0.2, 30.0, 30.1, 60.0, 90.0, 90.1]
    for i, s in enumerate(starts):
        # Mid-command jitter: 'a' at s, 'b' 0.01s later, 'c' 2s later, '\r' 2.05s later
        events.append((s, "i", "a"))
        events.append((s + 0.01, "i", "b"))
        events.append((s + 2.0, "i", "c"))
        events.append((s + 2.05, "i", "\r"))
        events.append((s + 2.10, "o", "bash: abc: command not found\n"))
    out = list(extract_session(events, sid="cl-high"))
    obs = _of(out, "cognitive.cognitive_load")
    assert obs.value == "high"


def test_low_sample_count_reduces_confidence() -> None:
    short = list(extract_session(_metronomic_clean_session(3), sid="cl-short"))
    full = list(extract_session(_metronomic_clean_session(8), sid="cl-full"))
    s = _of(short, "cognitive.cognitive_load")
    f = _of(full, "cognitive.cognitive_load")
    assert s.confidence < f.confidence


def test_pii_no_command_bodies_in_observation() -> None:
    events: list[AsciinemaEvent] = []
    for i in range(6):
        events.extend(_typed("supersecret\r", t0=i * 1.0, dt=0.05))
    out = list(extract_session(events, sid="cl-pii"))
    obs = _of(out, "cognitive.cognitive_load")
    assert "supersecret" not in obs.model_dump_json()
