# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step D.7: ``cognitive.error_resilience.fallback_to_man``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


PRIMITIVE = "cognitive.error_resilience.fallback_to_man"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed(text: str, t0: float, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


def _err_then(token: str, response: str, t0: float) -> list[AsciinemaEvent]:
    events = _typed(f"{token}\r", t0=t0)
    cmd_end = t0 + len(token) * 0.05
    events.append((cmd_end + 0.10, "o", f"bash: {token}: command not found\n"))
    events.extend(_typed(f"{response}\r", t0=t0 + 1.5))
    return events


def test_no_errors_no_emission() -> None:
    events = _typed("ls\r", t0=0.0) + [(0.5, "o", "file1\n")]
    out = list(extract_session(events, sid="ftm-clean"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_help_after_error_emits_present() -> None:
    """At least one fallback to a help-family token → present."""
    events: list[AsciinemaEvent] = []
    for i in range(5):
        events.extend(_err_then("foo", "man", t0=i * 3.0))
    out = list(extract_session(events, sid="ftm-present"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "present"


def test_pivot_unrelated_emits_absent() -> None:
    """Errors followed by non-help tools → absent."""
    events: list[AsciinemaEvent] = []
    for i in range(5):
        events.extend(_err_then("foo", "ls", t0=i * 3.0))
    out = list(extract_session(events, sid="ftm-absent"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "absent"


def test_info_token_also_counts() -> None:
    events: list[AsciinemaEvent] = []
    for i in range(5):
        events.extend(_err_then("foo", "info", t0=i * 3.0))
    out = list(extract_session(events, sid="ftm-info"))
    assert _of(out, PRIMITIVE).value == "present"


def test_low_error_count_reduces_confidence() -> None:
    short_events: list[AsciinemaEvent] = []
    for i in range(2):
        short_events.extend(_err_then("foo", "man", t0=i * 3.0))
    full_events: list[AsciinemaEvent] = []
    for i in range(6):
        full_events.extend(_err_then("foo", "man", t0=i * 3.0))
    s = _of(list(extract_session(short_events, sid="ftm-short")), PRIMITIVE)
    f = _of(list(extract_session(full_events, sid="ftm-full")), PRIMITIVE)
    assert s.confidence < f.confidence
