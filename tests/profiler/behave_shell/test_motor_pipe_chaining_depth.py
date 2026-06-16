# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step C.3: ``motor.shell_mastery.pipe_chaining_depth``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._ctx import build_session_context
from decnet.profiler.behave_shell._parse import AsciinemaEvent

PRIMITIVE = "motor.shell_mastery.pipe_chaining_depth"


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _command(t0: float, body: str) -> list[AsciinemaEvent]:
    events: list[AsciinemaEvent] = []
    t = t0
    for c in body:
        events.append((t, "i", c))
        t += 0.05
    events.append((t, "i", "\r"))
    return events


def _session(bodies: list[str], gap: float = 1.0) -> list[AsciinemaEvent]:
    events: list[AsciinemaEvent] = []
    t = 0.0
    for body in bodies:
        events.extend(_command(t, body))
        t = events[-1][0] + gap
    return events


def test_no_commands_no_emission() -> None:
    out = list(extract_session([(0.0, "i", "ls")], sid="pipe-empty"))
    assert [o for o in out if o.primitive == PRIMITIVE] == []


def test_no_pipes_emit_shallow() -> None:
    out = list(extract_session(_session(["ls", "pwd", "id", "uname", "whoami"]),
                               sid="pipe-shallow"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "shallow"
    assert obs.confidence == 0.70


def test_one_stage_pipeline_emit_shallow() -> None:
    # median = 1 → shallow.
    out = list(extract_session(_session(["ls | wc"] * 5), sid="pipe-one"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "shallow"


def test_two_stage_pipeline_emit_moderate() -> None:
    # median = 2 → moderate.
    out = list(extract_session(_session(["ls | grep x | wc"] * 5),
                               sid="pipe-moderate"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "moderate"


def test_three_stage_pipeline_emit_deep() -> None:
    # median = 3 → deep.
    out = list(extract_session(_session(["ls | grep x | sort | uniq"] * 5),
                               sid="pipe-deep"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "deep"


def test_pasted_pipeline_still_counts() -> None:
    """Pipes inside a paste-burst event count toward pipe_count — the
    operator chose to execute the pipeline, regardless of provenance."""
    # Single big paste event then \r — one command.
    events: list[AsciinemaEvent] = [
        (0.0, "i", "ls | grep x | sort | uniq | wc"),
        (0.1, "i", "\r"),
    ]
    # Need ≥5 commands to get past the SHELL_MASTERY_MIN_COMMANDS gate.
    t = 1.0
    for _ in range(4):
        events.append((t, "i", "ls | grep x | sort | uniq | wc"))
        events.append((t + 0.1, "i", "\r"))
        t += 1.0
    out = list(extract_session(events, sid="pipe-pasted"))
    obs = _of(out, PRIMITIVE)
    assert obs.value == "deep"


def test_few_commands_drops_confidence() -> None:
    out = list(extract_session(_session(["ls", "pwd", "id"]),
                               sid="pipe-low-n"))
    obs = _of(out, PRIMITIVE)
    assert obs.confidence == 0.40


def test_segmentation_populates_pipe_count() -> None:
    events = _command(0.0, "ls | grep x | wc") + _command(5.0, "pwd")
    ctx = build_session_context(events, sid="seg-pipe", source="t")
    assert len(ctx.commands) == 2
    assert ctx.commands[0].pipe_count == 2
    assert ctx.commands[1].pipe_count == 0
