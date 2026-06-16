# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step G.7: ``emotional_valence.stress_response`` ∈ {none,
eustress_positive, distress_negative}.

Hard 0.5 confidence cap.
"""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "emotional_valence.stress_response"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def _cmd_with_error(token: str, t0: float, dt: float = 0.05) -> list[AsciinemaEvent]:
    """Emit one command followed by an error-fingerprint output line."""
    events = _typed(f"{token}\r", t0=t0, dt=dt)
    cmd_end = t0 + len(token) * dt
    events.append((cmd_end + 0.10, "o", "bash: command not found\nanti@host:~$ "))
    return events


def _cmd_ok(token: str, t0: float, dt: float = 0.05) -> list[AsciinemaEvent]:
    events = _typed(f"{token}\r", t0=t0, dt=dt)
    cmd_end = t0 + len(token) * dt
    events.append((cmd_end + 0.10, "o", "out\nanti@host:~$ "))
    return events


def test_no_commands_no_emission() -> None:
    out = list(extract_session([(0.0, "i", "x")], sid="g7-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_no_errors_emits_none() -> None:
    events = _cmd_ok("hostname", t0=0.0) + _cmd_ok("date", t0=2.0)
    obs = _of(list(extract_session(events, sid="g7-noerr")), PRIMITIVE)
    assert obs.value == "none"


def test_distress_post_error_speed_up() -> None:
    """After an error, the operator types the next command faster."""
    events = (
        _cmd_ok("hostname", t0=0.0, dt=0.20)
        + _cmd_ok("date", t0=2.0, dt=0.20)
        + _cmd_with_error("foobar", t0=4.0, dt=0.20)
        + _cmd_ok("hostname", t0=6.0, dt=0.04)        # post-error: fast
        + _cmd_with_error("baz", t0=8.0, dt=0.20)
        + _cmd_ok("date", t0=10.0, dt=0.04)           # post-error: fast
        + _cmd_ok("hostname", t0=12.0, dt=0.20)
    )
    obs = _of(list(extract_session(events, sid="g7-dist")), PRIMITIVE)
    assert obs.value == "distress_negative"


def test_eustress_post_error_slow_down() -> None:
    """After an error, the operator slows down — deliberate recovery."""
    events = (
        _cmd_ok("hostname", t0=0.0, dt=0.04)
        + _cmd_ok("date", t0=2.0, dt=0.04)
        + _cmd_with_error("foobar", t0=4.0, dt=0.04)
        + _cmd_ok("hostname", t0=6.0, dt=0.20)        # post-error: slow
        + _cmd_with_error("baz", t0=8.0, dt=0.04)
        + _cmd_ok("date", t0=10.0, dt=0.20)           # post-error: slow
        + _cmd_ok("hostname", t0=12.0, dt=0.04)
    )
    obs = _of(list(extract_session(events, sid="g7-eu")), PRIMITIVE)
    assert obs.value == "eustress_positive"


def test_confidence_capped_at_05() -> None:
    events = (
        _cmd_with_error("foobar", t0=0.0, dt=0.05)
        + _cmd_ok("hostname", t0=2.0, dt=0.20)
        + _cmd_with_error("baz", t0=4.0, dt=0.05)
        + _cmd_ok("date", t0=6.0, dt=0.20)
    )
    obs = _of(list(extract_session(events, sid="g7-cap")), PRIMITIVE)
    assert obs.confidence <= 0.50
