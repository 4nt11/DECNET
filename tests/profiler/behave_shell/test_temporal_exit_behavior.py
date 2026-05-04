"""Step E.4: ``temporal.lifecycle_markers.exit_behavior`` (unblocked by F.0)."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "temporal.lifecycle_markers.exit_behavior"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def _cmd(token: str, t0: float, *, with_prompt: bool = True) -> list[AsciinemaEvent]:
    """Emit one command + (optionally) a trailing prompt-line."""
    events = _typed(f"{token}\r", t0=t0)
    cmd_end = t0 + len(token) * 0.05
    if with_prompt:
        events.append((cmd_end + 0.10, "o", "out\nanti@host:~$ "))
    else:
        events.append((cmd_end + 0.10, "o", "out\n"))
    return events


def test_no_commands_no_emission() -> None:
    out = list(extract_session([(0.0, "i", "x")], sid="ex-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_last_command_no_prompt_emits_abrupt() -> None:
    """Session cut mid-output → no trailing prompt → abrupt."""
    events = _cmd("ls", t0=0.0) + _cmd("foo", t0=1.0, with_prompt=False)
    obs = _of(list(extract_session(events, sid="ex-abrupt")), PRIMITIVE)
    assert obs.value == "abrupt"


def test_explicit_exit_token_emits_graceful() -> None:
    events = _cmd("ls", t0=0.0) + _cmd("exit", t0=1.0)
    obs = _of(list(extract_session(events, sid="ex-graceful")), PRIMITIVE)
    assert obs.value == "graceful"


def test_logout_token_emits_graceful() -> None:
    events = _cmd("ls", t0=0.0) + _cmd("logout", t0=1.0)
    obs = _of(list(extract_session(events, sid="ex-logout")), PRIMITIVE)
    assert obs.value == "graceful"


def test_cleanup_token_in_tail_emits_cleanup() -> None:
    """Last few commands include cleanup vocabulary → cleanup."""
    events = (
        _cmd("ls", t0=0.0)
        + _cmd("cat", t0=1.0)
        + _cmd("history", t0=2.0)  # cleanup-family token in tail
    )
    obs = _of(list(extract_session(events, sid="ex-cleanup")), PRIMITIVE)
    assert obs.value == "cleanup"


def test_clean_session_with_prompt_emits_graceful() -> None:
    """Trailing prompt + no exit/cleanup tokens → graceful (Ctrl-D path)."""
    events = _cmd("ls", t0=0.0) + _cmd("ps", t0=1.0) + _cmd("cat", t0=2.0)
    obs = _of(list(extract_session(events, sid="ex-clean")), PRIMITIVE)
    assert obs.value == "graceful"


def test_abrupt_lower_confidence_than_graceful() -> None:
    abrupt_events = _cmd("ls", t0=0.0) + _cmd("foo", t0=1.0, with_prompt=False)
    graceful_events = _cmd("ls", t0=0.0) + _cmd("exit", t0=1.0)
    a = _of(list(extract_session(abrupt_events, sid="ex-a")), PRIMITIVE)
    g = _of(list(extract_session(graceful_events, sid="ex-g")), PRIMITIVE)
    assert a.confidence < g.confidence
