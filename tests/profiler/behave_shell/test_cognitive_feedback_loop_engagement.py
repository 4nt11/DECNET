# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step 7: ``cognitive.feedback_loop_engagement``."""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def _of(observations: list, primitive: str):
    obs = [o for o in observations if o.primitive == primitive]
    assert len(obs) == 1, f"expected exactly one {primitive}, got {len(obs)}"
    return obs[0]


def _session_with_pairs(
    output_byte_counts: list[int],
    next_pauses: list[float],
) -> list[AsciinemaEvent]:
    """Build a session with N+1 commands, where the i-th (i in 0..N-1)
    is followed by ``output_byte_counts[i]`` bytes of output, then a
    pause of ``next_pauses[i]`` seconds, then the next command."""
    assert len(output_byte_counts) == len(next_pauses)
    events: list[AsciinemaEvent] = []
    t = 0.0
    for bytes_after, pause in zip(output_byte_counts, next_pauses):
        # Issue command at t
        events.append((t, "i", "x\r"))
        # Emit one output event of the desired size shortly after
        events.append((t + 0.01, "o", "y" * bytes_after))
        # Next command starts after `pause`
        t += pause
    # Final terminating command
    events.append((t, "i", "x\r"))
    return events


def test_no_output_events_emits_unknown() -> None:
    # Only input, no output → unknown @ 1.0
    events: list[AsciinemaEvent] = [(i * 1.0, "i", "x\r") for i in range(8)]
    out = list(extract_session(events, sid="fb-no-output"))
    obs = _of(out, "cognitive.feedback_loop_engagement")
    assert obs.value == "unknown"
    assert obs.confidence == 1.0


def test_few_pairs_emits_unknown() -> None:
    # 2 commands → 1 pair, below the min-pairs floor
    events: list[AsciinemaEvent] = [
        (0.0, "i", "x\r"),
        (0.1, "o", "out"),
        (1.0, "i", "x\r"),
    ]
    out = list(extract_session(events, sid="fb-few"))
    obs = _of(out, "cognitive.feedback_loop_engagement")
    assert obs.value == "unknown"


def test_strong_positive_correlation_closed_loop() -> None:
    # Larger output → longer pause: closed_loop
    bytes_seen = [10, 100, 1000, 200, 50, 800]
    pauses    = [1.0, 5.0, 20.0, 6.0, 2.0, 18.0]
    out = list(extract_session(
        _session_with_pairs(bytes_seen, pauses),
        sid="fb-closed",
    ))
    obs = _of(out, "cognitive.feedback_loop_engagement")
    assert obs.value == "closed_loop"
    assert obs.confidence == 0.75


def test_zero_correlation_fire_and_forget() -> None:
    # Constant pace independent of output: fire_and_forget
    bytes_seen = [10, 1000, 50, 800, 5, 200]
    pauses    = [3.0, 3.0, 3.0, 3.0, 3.0, 3.0]
    out = list(extract_session(
        _session_with_pairs(bytes_seen, pauses),
        sid="fb-fnf",
    ))
    obs = _of(out, "cognitive.feedback_loop_engagement")
    # statistics.correlation raises on constant series; we map that
    # to "unknown". A near-zero (non-constant) correlation maps to
    # fire_and_forget. Either is correct here as long as it's NOT
    # closed_loop.
    assert obs.value in ("fire_and_forget", "unknown")
    assert obs.value != "closed_loop"


def test_negative_correlation_not_closed_loop() -> None:
    # Big output, short pause / small output, long pause: negative r
    bytes_seen = [10, 1000, 50, 800, 5, 200]
    pauses    = [20.0, 1.0, 18.0, 2.0, 22.0, 5.0]
    out = list(extract_session(
        _session_with_pairs(bytes_seen, pauses),
        sid="fb-neg",
    ))
    obs = _of(out, "cognitive.feedback_loop_engagement")
    # Negative r is below FEEDBACK_CORRELATION_MIN (0.30) so it
    # belongs to the fire_and_forget bucket — closed_loop is reserved
    # for r > +0.30.
    assert obs.value == "fire_and_forget"


def test_no_commands_no_emission() -> None:
    # No commands at all → not emitted (no honest answer)
    out = list(extract_session([(0.0, "o", "hi")], sid="fb-nocmd"))
    assert [o for o in out if o.primitive == "cognitive.feedback_loop_engagement"] == []
