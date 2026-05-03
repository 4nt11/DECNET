"""Step 0 smoke: prove the wiring before any logic.

Before any feature function lands, verify:

* the public ``extract_session`` import path resolves;
* an empty event stream yields zero observations and a well-formed
  zero-duration ``SessionContext``;
* a single input event yields a context with ``t_start == t_end``
  and ``duration_s == 0.0``;
* a multi-event stream populates ``t_start`` / ``t_end`` /
  ``duration_s`` correctly and routes events into the
  ``input_events`` / ``output_events`` slots by kind;
* ``FEATURES`` is empty at Step 0 — the empty contract is the gate
  that the next step must intentionally break.
"""
from __future__ import annotations

from decnet.profiler.behave_shell import (
    DEFAULT_SOURCE,
    build_context,
    extract_session,
)
from decnet.profiler.behave_shell._features import FEATURES
from decnet.profiler.behave_shell._parse import AsciinemaEvent


def test_features_tuple_is_empty_at_step_0() -> None:
    assert FEATURES == ()


def test_default_source_is_canonical_path() -> None:
    assert DEFAULT_SOURCE == "decnet/profiler/behave_shell/extract.py"


def test_extract_session_empty_stream_yields_no_observations() -> None:
    out = list(extract_session([], sid="sess-empty"))
    assert out == []


def test_build_context_empty_stream_zero_duration() -> None:
    ctx = build_context([], sid="sess-empty")
    assert ctx.sid == "sess-empty"
    assert ctx.source == DEFAULT_SOURCE
    assert ctx.evidence_ref == "session:sess-empty"
    assert ctx.t_start == 0.0
    assert ctx.t_end == 0.0
    assert ctx.duration_s == 0.0
    assert ctx.input_events == ()
    assert ctx.output_events == ()


def test_build_context_single_input_event() -> None:
    events: list[AsciinemaEvent] = [(1.5, "i", "a")]
    ctx = build_context(events, sid="sess-1")
    assert ctx.t_start == 1.5
    assert ctx.t_end == 1.5
    assert ctx.duration_s == 0.0
    assert ctx.input_events == ((1.5, "i", "a"),)
    assert ctx.output_events == ()


def test_build_context_multi_event_routes_by_kind() -> None:
    events: list[AsciinemaEvent] = [
        (0.0, "i", "l"),
        (0.1, "i", "s"),
        (0.2, "o", "ls\r\n"),
        (0.3, "o", "file.txt\r\n"),
        (0.5, "i", "\r"),
    ]
    ctx = build_context(events, sid="sess-multi")
    assert ctx.t_start == 0.0
    assert ctx.t_end == 0.5
    assert ctx.duration_s == 0.5
    assert len(ctx.input_events) == 3
    assert len(ctx.output_events) == 2
    # Order preserved
    assert ctx.input_events[0] == (0.0, "i", "l")
    assert ctx.output_events[-1] == (0.3, "o", "file.txt\r\n")


def test_extract_session_explicit_evidence_ref_overrides_default() -> None:
    ctx = build_context(
        [(0.0, "i", "x")],
        sid="sess-x",
        evidence_ref="shard:/var/log/d/sess-x.cast",
    )
    assert ctx.evidence_ref == "shard:/var/log/d/sess-x.cast"


def test_extract_session_with_features_still_empty() -> None:
    """Until Step 2 lands, even a populated stream emits nothing."""
    events: list[AsciinemaEvent] = [(t / 10.0, "i", c) for t, c in enumerate("hello\r")]
    out = list(extract_session(events, sid="sess-features-empty"))
    assert out == []
