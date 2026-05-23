# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step G.4: ``operational.multi_actor_indicators`` ∈ {solo, handoff_detected}.

``team_coordinated`` is Tier B (cross-session) — never emitted here.
"""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "operational.multi_actor_indicators"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def _cmd(token: str, t0: float, dt: float = 0.05) -> list[AsciinemaEvent]:
    """Emit one command (no prompt — output unused for this primitive)."""
    events = _typed(f"{token}\r", t0=t0, dt=dt)
    return events


def test_too_few_commands_no_emission() -> None:
    events: list[AsciinemaEvent] = []
    for i in range(5):
        events += _cmd("ls", t0=float(i))
    out = list(extract_session(events, sid="g4-thin"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_solo_consistent_typing() -> None:
    """Same dt across both halves → small delta → solo."""
    events: list[AsciinemaEvent] = []
    for i in range(10):
        events += _cmd("hostname", t0=float(i * 2), dt=0.10)
    obs = _of(list(extract_session(events, sid="g4-solo")), PRIMITIVE)
    assert obs.value == "solo"


def test_handoff_detected_speed_jump() -> None:
    """First half slow typing (dt=0.20), second half fast (dt=0.05)."""
    events: list[AsciinemaEvent] = []
    for i in range(8):
        events += _cmd("hostname", t0=float(i * 2), dt=0.20)
    for i in range(8):
        events += _cmd("hostname", t0=float(20 + i * 2), dt=0.05)
    obs = _of(list(extract_session(events, sid="g4-handoff")), PRIMITIVE)
    assert obs.value == "handoff_detected"


def test_team_coordinated_never_emitted() -> None:
    """Tier B value must never appear, regardless of input."""
    events: list[AsciinemaEvent] = []
    for i in range(20):
        dt = 0.10 + (0.20 if i % 2 else 0.0)
        events += _cmd("hostname", t0=float(i * 2), dt=dt)
    obs = _of(list(extract_session(events, sid="g4-no-team")), PRIMITIVE)
    assert obs.value in ("solo", "handoff_detected")


def test_high_count_raises_confidence() -> None:
    events: list[AsciinemaEvent] = []
    for i in range(20):
        events += _cmd("hostname", t0=float(i * 2), dt=0.10)
    obs = _of(list(extract_session(events, sid="g4-conf")), PRIMITIVE)
    assert obs.confidence == 0.55
