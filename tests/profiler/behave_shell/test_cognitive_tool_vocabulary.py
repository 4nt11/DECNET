# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step D.4: ``cognitive.tool_vocabulary``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _cmds(tokens: list[str]) -> list[AsciinemaEvent]:
    events: list[AsciinemaEvent] = []
    for i, tok in enumerate(tokens):
        t0 = i * 1.0
        for j, c in enumerate(tok):
            events.append((t0 + j * 0.05, "i", c))
        events.append((t0 + len(tok) * 0.05, "i", "\r"))
    return events


def test_no_commands_no_emission() -> None:
    out = list(extract_session([(0.0, "i", "x")], sid="tv-empty"))
    assert [o for o in out if o.primitive == "cognitive.tool_vocabulary"] == []


def test_few_distinct_tools_emit_narrow() -> None:
    out = list(extract_session(
        _cmds(["ls", "ls", "ps", "ps", "ls", "ps", "ls", "ps"]),
        sid="tv-narrow",
    ))
    obs = _of(out, "cognitive.tool_vocabulary")
    assert obs.value == "narrow"


def test_mid_distinct_emit_moderate() -> None:
    out = list(extract_session(
        _cmds(["ls", "ps", "id", "uname", "whoami", "pwd"]),
        sid="tv-mod",
    ))
    obs = _of(out, "cognitive.tool_vocabulary")
    assert obs.value == "moderate"


def test_many_distinct_tools_emit_broad() -> None:
    out = list(extract_session(
        _cmds(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]),
        sid="tv-broad",
    ))
    obs = _of(out, "cognitive.tool_vocabulary")
    assert obs.value == "broad"


def test_low_sample_count_reduces_confidence() -> None:
    short = list(extract_session(_cmds(["a", "b"]), sid="tv-short"))
    full = list(extract_session(_cmds(["a", "b", "c", "d", "e", "f"]), sid="tv-full"))
    s = _of(short, "cognitive.tool_vocabulary")
    f = _of(full, "cognitive.tool_vocabulary")
    assert s.confidence < f.confidence
