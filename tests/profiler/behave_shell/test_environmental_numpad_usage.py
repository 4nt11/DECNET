"""Step F.5: ``environmental.numpad_usage``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "environmental.numpad_usage"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.10) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def test_below_min_typed_chars_no_emission() -> None:
    out = list(extract_session(_typed("ls\r"), sid="np-tiny"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_no_digit_runs_emits_not_detected() -> None:
    """50+ typed chars, none of them digit runs → not_detected."""
    text = "the quick brown fox jumps over the lazy dog repeatedly\r"
    out = list(extract_session(_typed(text, dt=0.10), sid="np-text"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "not_detected"


def test_slow_digit_typing_not_detected() -> None:
    """Slow digit typing (typing-speed cadence) → not_detected."""
    # 100ms IAT between digits — too slow for numpad
    text = "1234567890" * 6 + "\r"  # 60 digits + return for command boundary
    out = list(extract_session(_typed(text, dt=0.10), sid="np-slow"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "not_detected"


def test_fast_digit_run_emits_detected() -> None:
    """Sub-50ms digit cadence over a 4+ run → detected."""
    # Build a session with 50+ chars first, then a fast digit burst
    events: list[AsciinemaEvent] = []
    # Filler typing (slow)
    for i, c in enumerate("the quick brown fox jumps over the lazy dog filler"):
        events.append((i * 0.10, "i", c))
    # Fast digit run starting at t=10s — IAT=20ms
    base = 10.0
    for i, d in enumerate("1234567890"):
        events.append((base + i * 0.020, "i", d))
    events.append((20.0, "i", "\r"))
    out = list(extract_session(events, sid="np-fast"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "detected"
