"""Step F.2: ``environmental.terminal_multiplexer``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "environmental.terminal_multiplexer"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def test_clean_pty_emits_none() -> None:
    events: list[AsciinemaEvent] = [
        *_typed("ls\r"),
        (0.20, "o", "file1\nfile2\n"),
    ]
    out = list(extract_session(events, sid="mux-clean"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "none"


def test_tmux_dcs_passthrough_detected() -> None:
    events: list[AsciinemaEvent] = [
        *_typed("ls\r"),
        (0.20, "o", "\x1bPtmux;passthrough_payload\x1b\\"),
    ]
    obs = _of(list(extract_session(events, sid="mux-tmux-dcs")), PRIMITIVE)
    assert obs.value == "tmux"


def test_tmux_focus_reporting_detected() -> None:
    events: list[AsciinemaEvent] = [
        *_typed("ls\r"),
        (0.20, "o", "\x1b[?1004h"),  # set focus reporting
    ]
    obs = _of(list(extract_session(events, sid="mux-tmux-focus")), PRIMITIVE)
    assert obs.value == "tmux"


def test_screen_dcs_detected() -> None:
    events: list[AsciinemaEvent] = [
        *_typed("ls\r"),
        (0.20, "o", "\x1bP=value\x1b\\"),
    ]
    obs = _of(list(extract_session(events, sid="mux-screen")), PRIMITIVE)
    assert obs.value == "screen"


def test_both_present_prefers_tmux() -> None:
    """Nested mux setup — prefer tmux (more common)."""
    events: list[AsciinemaEvent] = [
        *_typed("ls\r"),
        (0.20, "o", "\x1bPtmux;\x1b\\\x1bP=screen\x1b\\"),
    ]
    obs = _of(list(extract_session(events, sid="mux-both")), PRIMITIVE)
    assert obs.value == "tmux"


def test_none_has_lower_confidence_than_detected() -> None:
    """``none`` could be a hidden multiplexer; confidence reflects that."""
    none_events: list[AsciinemaEvent] = _typed("ls\r") + [(0.20, "o", "file1\n")]
    tmux_events: list[AsciinemaEvent] = _typed("ls\r") + [(0.20, "o", "\x1bPtmux;\x1b\\")]
    n = _of(list(extract_session(none_events, sid="mux-n")), PRIMITIVE)
    t = _of(list(extract_session(tmux_events, sid="mux-t")), PRIMITIVE)
    assert n.confidence < t.confidence
