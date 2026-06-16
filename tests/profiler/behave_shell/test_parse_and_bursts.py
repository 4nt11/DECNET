# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step 1: shard parsing + paste-burst detection.

Synthetic streams covering pure-typed, pure-pasted, and mixed input,
plus the JSONL shard line parser and its junk handling.
"""
from __future__ import annotations

import json

from decnet.profiler.behave_shell._ctx import build_session_context
from decnet.profiler.behave_shell._parse import (
    PasteBurst,
    parse_shard,
    parse_shard_line,
)


# ── parse_shard_line ───────────────────────────────────────────────────────

def test_parse_shard_line_event() -> None:
    line = json.dumps({"sid": "x", "t": 1.5, "ch": "i", "d": "ls"})
    assert parse_shard_line(line) == (1.5, "i", "ls")


def test_parse_shard_line_skips_header() -> None:
    line = json.dumps({"sid": "x", "hdr": {"version": 2}})
    assert parse_shard_line(line) is None


def test_parse_shard_line_handles_blank_and_garbage() -> None:
    assert parse_shard_line("") is None
    assert parse_shard_line("   ") is None
    assert parse_shard_line("not json") is None
    assert parse_shard_line('{"t": "string-not-number", "ch": "i", "d": "x"}') is None
    assert parse_shard_line('{"t": 1.0, "ch": "z", "d": "x"}') is None  # bad kind
    assert parse_shard_line('"just a string"') is None


def test_parse_shard_skips_junk_in_stream() -> None:
    lines = [
        json.dumps({"sid": "x", "hdr": {"version": 2}}),
        "",
        "garbage",
        json.dumps({"sid": "x", "t": 0.1, "ch": "i", "d": "a"}),
        json.dumps({"sid": "x", "t": 0.2, "ch": "o", "d": "a\r\n"}),
    ]
    out = list(parse_shard(lines))
    assert out == [(0.1, "i", "a"), (0.2, "o", "a\r\n")]


# ── paste-burst detection ──────────────────────────────────────────────────

def test_pure_typed_stream_has_no_paste_bursts() -> None:
    # Single-char input events spaced by 0.1s: pure typing.
    events = [(i * 0.1, "i", c) for i, c in enumerate("hello world\r")]
    ctx = build_session_context(events, sid="t-typed", source="test")
    assert ctx.paste_bursts == ()
    assert ctx.paste_event_count == 0
    # IATs computed correctly
    assert len(ctx.iats) == len(events) - 1
    for iat in ctx.iats:
        assert abs(iat - 0.1) < 1e-9


def test_single_paste_event_one_burst() -> None:
    events = [
        (0.0, "i", "echo hello world\r"),  # 17 chars — paste class
    ]
    ctx = build_session_context(events, sid="t-paste-1", source="test")
    assert len(ctx.paste_bursts) == 1
    assert ctx.paste_event_count == 1
    burst = ctx.paste_bursts[0]
    assert burst.start_ts == 0.0
    assert burst.end_ts == 0.0
    assert burst.char_count == 17
    assert burst.event_count == 1


def test_two_close_paste_events_collapse_into_one_burst() -> None:
    events = [
        (0.0, "i", "first paste line\r"),
        (0.05, "i", "second paste line\r"),  # within PASTE_BURST_MAX_IAT_S
    ]
    ctx = build_session_context(events, sid="t-paste-2", source="test")
    assert len(ctx.paste_bursts) == 1
    assert ctx.paste_event_count == 2
    assert ctx.paste_bursts[0].event_count == 2
    assert ctx.paste_bursts[0].char_count == 17 + 18


def test_two_far_paste_events_split_into_two_bursts() -> None:
    events = [
        (0.0, "i", "first paste\r"),
        (5.0, "i", "second paste\r"),  # well past the IAT cap
    ]
    ctx = build_session_context(events, sid="t-paste-far", source="test")
    assert len(ctx.paste_bursts) == 2
    assert ctx.paste_event_count == 2


def test_typing_between_pastes_breaks_the_burst() -> None:
    events: list = [
        (0.0, "i", "long pasted line\r"),
        (0.5, "i", "x"),  # single typed char interrupts
        (0.6, "i", "another pasted line\r"),
    ]
    ctx = build_session_context(events, sid="t-mixed", source="test")
    assert len(ctx.paste_bursts) == 2
    assert ctx.paste_event_count == 2
    # The "x" event is not a paste-class event
    assert ctx.input_events[1][2] == "x"


def test_paste_burst_record_is_immutable() -> None:
    b = PasteBurst(start_ts=0.0, end_ts=1.0, char_count=10, event_count=1)
    try:
        b.char_count = 99  # type: ignore[misc]
    except Exception:
        pass
    else:
        raise AssertionError("PasteBurst should be frozen")
