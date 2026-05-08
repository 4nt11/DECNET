"""Step G.3: ``operational.cleanup_behavior`` ∈ {thorough, partial, none}."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "operational.cleanup_behavior"


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
    out = list(extract_session([(0.0, "i", "x")], sid="g3-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_thorough_three_distinct_cleanup_in_tail() -> None:
    events = (
        _cmd("ls", t0=0.0)
        + _cmd("history", t0=1.0)
        + _cmd("rm", t0=2.0)
        + _cmd("shred", t0=3.0)
        + _cmd("clear", t0=4.0)
    )
    obs = _of(list(extract_session(events, sid="g3-thorough")), PRIMITIVE)
    assert obs.value == "thorough"


def test_partial_two_distinct_cleanup() -> None:
    events = (
        _cmd("ls", t0=0.0)
        + _cmd("pwd", t0=1.0)
        + _cmd("rm", t0=2.0)
        + _cmd("clear", t0=3.0)
    )
    obs = _of(list(extract_session(events, sid="g3-partial")), PRIMITIVE)
    assert obs.value == "partial"


def test_none_no_cleanup() -> None:
    events = (
        _cmd("ls", t0=0.0)
        + _cmd("pwd", t0=1.0)
        + _cmd("cat", t0=2.0)
    )
    obs = _of(list(extract_session(events, sid="g3-none")), PRIMITIVE)
    assert obs.value == "none"


def test_low_command_count_lower_confidence() -> None:
    events = _cmd("ls", t0=0.0) + _cmd("pwd", t0=1.0)
    obs = _of(list(extract_session(events, sid="g3-thin")), PRIMITIVE)
    assert obs.confidence == 0.35


def test_high_command_count_higher_confidence() -> None:
    events: list[AsciinemaEvent] = []
    for i, tok in enumerate(["ls", "pwd", "cat", "find", "ps", "ss", "id", "uname", "rm", "clear"]):
        events += _cmd(tok, t0=float(i))
    obs = _of(list(extract_session(events, sid="g3-conf")), PRIMITIVE)
    assert obs.confidence == 0.55


def test_only_tail_window_counts() -> None:
    """``rm`` early then 5 recon commands → tail has zero cleanup → none."""
    events = (
        _cmd("rm", t0=0.0)
        + _cmd("ls", t0=1.0)
        + _cmd("pwd", t0=2.0)
        + _cmd("cat", t0=3.0)
        + _cmd("find", t0=4.0)
        + _cmd("ps", t0=5.0)
        + _cmd("ss", t0=6.0)
    )
    obs = _of(list(extract_session(events, sid="g3-window")), PRIMITIVE)
    assert obs.value == "none"
