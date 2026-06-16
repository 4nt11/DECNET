# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step B.4: ``motor.command_chunking``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _typed_command(start_ts: float, chars: str, iat: float) -> list[AsciinemaEvent]:
    """Build a typed command starting at ``start_ts`` with uniform IAT
    between chars. Terminates with ``\\r``."""
    events: list[AsciinemaEvent] = []
    t = start_ts
    for c in chars:
        events.append((t, "i", c))
        t += iat
    events.append((t, "i", "\r"))
    return events


def test_no_commands_no_emission() -> None:
    out = list(extract_session([(0.0, "i", "ls")], sid="cc-empty"))
    assert [o for o in out if o.primitive == "motor.command_chunking"] == []


def test_single_command_emits_single_command() -> None:
    events = _typed_command(0.0, "ls -la", 0.1)
    out = list(extract_session(events, sid="cc-single"))
    obs = _of(out, "motor.command_chunking")
    assert obs.value == "single_command"
    assert obs.confidence == 0.80


def test_uniform_intra_command_typing_emits_fluent() -> None:
    events = []
    for i in range(4):
        events += _typed_command(i * 5.0, "ls -la", 0.1)
    out = list(extract_session(events, sid="cc-fluent"))
    obs = _of(out, "motor.command_chunking")
    assert obs.value == "fluent"


def test_high_intra_command_variance_emits_fragmented() -> None:
    # Per-command IATs drawn so within-command CV >= 0.50: alternating
    # very-fast and very-slow keystrokes.
    events: list[AsciinemaEvent] = []
    base = 0.0
    for cmd_idx in range(3):
        t = base
        for j, c in enumerate("hello"):
            events.append((t, "i", c))
            # Alternate fast/slow → high CV inside each command
            t += 0.05 if j % 2 == 0 else 0.50
        events.append((t, "i", "\r"))
        base += 5.0
    out = list(extract_session(events, sid="cc-fragmented"))
    obs = _of(out, "motor.command_chunking")
    assert obs.value == "fragmented"


def test_paste_only_multi_command_no_emission() -> None:
    # Each command arrives as one paste event — no within-command IATs
    events: list[AsciinemaEvent] = [
        (0.0, "i", "echo aaaa\r"),
        (1.0, "i", "echo bbbb\r"),
        (2.0, "i", "echo cccc\r"),
    ]
    out = list(extract_session(events, sid="cc-paste-only"))
    assert [o for o in out if o.primitive == "motor.command_chunking"] == []
