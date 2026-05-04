"""Step D.5: ``cognitive.error_resilience.retry_tactic``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "cognitive.error_resilience.retry_tactic"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def _err_then(token: str, next_token: str | None, t0: float = 0.0) -> list[AsciinemaEvent]:
    """``token`` errors; ``next_token`` is the operator's response (or None).

    Output event lands after the ``\\r`` so it falls inside the
    command's post-execution window.
    """
    events: list[AsciinemaEvent] = []
    events.extend(_typed(f"{token}\r", t0=t0))
    cmd_end = t0 + len(token) * 0.05  # \r is the last char
    events.append((cmd_end + 0.10, "o", f"bash: {token}: command not found\n"))
    if next_token is not None:
        events.extend(_typed(f"{next_token}\r", t0=t0 + 1.5))
    return events


def test_no_errors_no_emission() -> None:
    events: list[AsciinemaEvent] = _typed("ls\r") + [(0.5, "o", "file1\n")]
    out = list(extract_session(events, sid="rt-noerr"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_majority_rerun_emits_rerun() -> None:
    """Operator re-invokes the same tool after each error → rerun."""
    events: list[AsciinemaEvent] = []
    for i in range(5):
        events.extend(_err_then("foo", "foo", t0=i * 2.0))
    out = list(extract_session(events, sid="rt-rerun"))
    assert _of(out, PRIMITIVE).value == "rerun"


def test_majority_switch_emits_switch() -> None:
    """Operator pivots to a different tool after each error → switch."""
    events: list[AsciinemaEvent] = []
    for i in range(5):
        events.extend(_err_then("foo", f"bar{i}", t0=i * 2.0))
    out = list(extract_session(events, sid="rt-switch"))
    assert _of(out, PRIMITIVE).value == "switch"


def test_terminal_error_emits_abort() -> None:
    """Single errored command at session end → abort (only candidate)."""
    events = _err_then("foo", None, t0=0.0)
    out = list(extract_session(events, sid="rt-abort"))
    assert _of(out, PRIMITIVE).value == "abort"


def test_low_error_count_reduces_confidence() -> None:
    short_events: list[AsciinemaEvent] = []
    for i in range(2):
        short_events.extend(_err_then("foo", "foo", t0=i * 2.0))
    full_events: list[AsciinemaEvent] = []
    for i in range(6):
        full_events.extend(_err_then("foo", "foo", t0=i * 2.0))
    s = _of(list(extract_session(short_events, sid="rt-short")), PRIMITIVE)
    f = _of(list(extract_session(full_events, sid="rt-full")), PRIMITIVE)
    assert s.confidence < f.confidence


def test_pii_no_command_bodies_in_observation() -> None:
    events: list[AsciinemaEvent] = []
    for i in range(5):
        events.extend(_err_then("supersecret", "supersecret", t0=i * 2.0))
    out = list(extract_session(events, sid="rt-pii"))
    obs = _of(out, PRIMITIVE)
    assert "supersecret" not in obs.model_dump_json()
