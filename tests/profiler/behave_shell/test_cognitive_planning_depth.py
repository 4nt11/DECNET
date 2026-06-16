# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step D.3: ``cognitive.planning_depth``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _commands_at(starts: list[float]) -> list[AsciinemaEvent]:
    events: list[AsciinemaEvent] = []
    for s in starts:
        events.append((s, "i", "x\r"))
    return events


def test_no_inter_cmd_iats_no_emission() -> None:
    out = list(extract_session(_commands_at([0.0]), sid="pd-empty"))
    assert [o for o in out if o.primitive == "cognitive.planning_depth"] == []


def test_long_pauses_emit_deep() -> None:
    """Most pauses > 1.5s → deep."""
    out = list(extract_session(
        _commands_at([0.0, 3.0, 6.0, 9.0, 12.0, 15.0, 18.0, 21.0]),
        sid="pd-deep",
    ))
    obs = _of(out, "cognitive.planning_depth")
    assert obs.value == "deep"


def test_sub_instant_pauses_emit_reactive() -> None:
    """Most pauses ≤ INTER_CMD_INSTANT_MAX (0.30s) → reactive."""
    out = list(extract_session(
        _commands_at([i * 0.10 for i in range(8)]),
        sid="pd-react",
    ))
    obs = _of(out, "cognitive.planning_depth")
    assert obs.value == "reactive"


def test_typing_speed_pauses_emit_shallow() -> None:
    """Pauses around 1s — neither deep nor reactive → shallow."""
    out = list(extract_session(
        _commands_at([i * 1.0 for i in range(8)]),
        sid="pd-shallow",
    ))
    obs = _of(out, "cognitive.planning_depth")
    assert obs.value == "shallow"


def test_low_sample_count_reduces_confidence() -> None:
    short = list(extract_session(_commands_at([0.0, 1.0, 2.0]), sid="pd-short"))
    full = list(extract_session(_commands_at([i * 1.0 for i in range(8)]), sid="pd-full"))
    s = _of(short, "cognitive.planning_depth")
    f = _of(full, "cognitive.planning_depth")
    assert s.confidence < f.confidence
