# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step G.2: ``operational.opsec_discipline`` ∈ {careful, careless, learning}."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "operational.opsec_discipline"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def _cmd(token: str, t0: float, *, with_prompt: bool = True) -> list[AsciinemaEvent]:
    events = _typed(f"{token}\r", t0=t0)
    cmd_end = t0 + len(token) * 0.05
    if with_prompt:
        events.append((cmd_end + 0.10, "o", "out\nanti@host:~$ "))
    else:
        events.append((cmd_end + 0.10, "o", "out\n"))
    return events


def test_no_commands_no_emission() -> None:
    out = list(extract_session([(0.0, "i", "x")], sid="g2-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_careless_no_history_tokens() -> None:
    events = _cmd("ls", t0=0.0) + _cmd("pwd", t0=1.0) + _cmd("cat", t0=2.0)
    obs = _of(list(extract_session(events, sid="g2-careless")), PRIMITIVE)
    assert obs.value == "careless"


def test_careful_history_then_cleanup_tail() -> None:
    """``history`` early + ``rm`` / ``shred`` in tail-3 → careful."""
    events = (
        _cmd("history", t0=0.0)
        + _cmd("ls", t0=1.0)
        + _cmd("pwd", t0=2.0)
        + _cmd("rm", t0=3.0)
        + _cmd("shred", t0=4.0)
        + _cmd("clear", t0=5.0)
    )
    obs = _of(list(extract_session(events, sid="g2-careful")), PRIMITIVE)
    assert obs.value == "careful"


def test_learning_history_no_cleanup_tail() -> None:
    """``history`` hit but tail is recon — knows the trick, doesn't apply."""
    events = (
        _cmd("history", t0=0.0)
        + _cmd("ls", t0=1.0)
        + _cmd("pwd", t0=2.0)
        + _cmd("cat", t0=3.0)
        + _cmd("find", t0=4.0)
    )
    obs = _of(list(extract_session(events, sid="g2-learning")), PRIMITIVE)
    assert obs.value == "learning"


def test_low_command_count_drops_confidence() -> None:
    events = _cmd("ls", t0=0.0) + _cmd("pwd", t0=1.0)
    obs = _of(list(extract_session(events, sid="g2-thin")), PRIMITIVE)
    assert obs.confidence == 0.30
    assert obs.value == "careless"
