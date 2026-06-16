# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step B.3: ``motor.error_correction``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def test_too_few_inputs_no_emission() -> None:
    events: list[AsciinemaEvent] = [(0.0, "i", "a"), (0.1, "i", "b")]
    out = list(extract_session(events, sid="ec-low"))
    assert [o for o in out if o.primitive == "motor.error_correction"] == []


def test_no_backspaces_no_kill_emits_absent() -> None:
    events: list[AsciinemaEvent] = [(i * 0.1, "i", c) for i, c in enumerate("hello\r")]
    out = list(extract_session(events, sid="ec-absent"))
    obs = _of(out, "motor.error_correction")
    assert obs.value == "absent"
    assert obs.confidence == 0.65


def test_kill_line_with_no_backspaces_emits_route_around() -> None:
    events: list[AsciinemaEvent] = [
        (0.0, "i", "l"),
        (0.1, "i", "s"),
        (0.2, "i", "\x15"),  # ^U — kill line
        (0.3, "i", "p"),
        (0.4, "i", "s"),
        (0.5, "i", "\r"),
    ]
    out = list(extract_session(events, sid="ec-route"))
    obs = _of(out, "motor.error_correction")
    assert obs.value == "route_around"


def test_backspace_within_500ms_emits_immediate() -> None:
    events: list[AsciinemaEvent] = [
        (0.0, "i", "h"),
        (0.1, "i", "e"),
        (0.2, "i", "y"),
        (0.30, "i", "\x7f"),  # backspace 100ms after 'y' — immediate
        (0.4, "i", "l"),
        (0.5, "i", "l"),
        (0.6, "i", "o"),
        (0.7, "i", "\r"),
    ]
    out = list(extract_session(events, sid="ec-immediate"))
    obs = _of(out, "motor.error_correction")
    assert obs.value == "immediate"


def test_backspace_after_long_pause_emits_deferred() -> None:
    events: list[AsciinemaEvent] = [
        (0.0, "i", "h"),
        (0.1, "i", "e"),
        (0.2, "i", "y"),
        # Backspace 2s after 'y' — deferred
        (2.2, "i", "\x7f"),
        (2.3, "i", "l"),
        (2.4, "i", "l"),
        (2.5, "i", "o"),
        (2.6, "i", "\r"),
    ]
    out = list(extract_session(events, sid="ec-deferred"))
    obs = _of(out, "motor.error_correction")
    assert obs.value == "deferred"


def test_pii_no_command_bodies_in_observation() -> None:
    events: list[AsciinemaEvent] = [(i * 0.1, "i", c) for i, c in enumerate("supersecret\r")]
    out = list(extract_session(events, sid="ec-pii"))
    obs = _of(out, "motor.error_correction")
    assert "supersecret" not in obs.model_dump_json()
