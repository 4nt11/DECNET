# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step 4: command segmentation in SessionContext.

PII discipline: full command body never enters the engine. Only the
first-token sha256 hash is retained.
"""
from __future__ import annotations

from decnet.profiler.behave_shell._ctx import build_session_context
from decnet.profiler.behave_shell._parse import AsciinemaEvent, hash_token


def _ctx(events: list[AsciinemaEvent]):
    return build_session_context(events, sid="t-cmds", source="test")


def test_no_input_means_no_commands() -> None:
    ctx = _ctx([])
    assert ctx.commands == ()
    assert ctx.inter_cmd_iats == ()
    assert ctx.output_per_cmd == ()


def test_unterminated_input_yields_no_command() -> None:
    # No trailing newline → no command boundary observed
    events: list[AsciinemaEvent] = [(0.0, "i", "ls"), (0.1, "i", " -la")]
    ctx = _ctx(events)
    assert ctx.commands == ()


def test_single_command_carriage_return_terminator() -> None:
    events: list[AsciinemaEvent] = [
        (0.0, "i", "l"), (0.1, "i", "s"), (0.2, "i", "\r"),
    ]
    ctx = _ctx(events)
    assert len(ctx.commands) == 1
    cmd = ctx.commands[0]
    assert cmd.start_ts == 0.0
    assert cmd.end_ts == 0.2
    assert cmd.first_token_hash == hash_token("ls")


def test_paste_event_with_full_command() -> None:
    # A pasted command line all in one event, terminated by \r in the
    # paste itself.
    events: list[AsciinemaEvent] = [(1.0, "i", "echo hello world\r")]
    ctx = _ctx(events)
    assert len(ctx.commands) == 1
    cmd = ctx.commands[0]
    assert cmd.first_token_hash == hash_token("echo")
    # start_ts and end_ts both come from the single event timestamp
    assert cmd.start_ts == 1.0
    assert cmd.end_ts == 1.0


def test_lf_terminator_also_segments() -> None:
    events: list[AsciinemaEvent] = [(0.0, "i", "ls -la\n")]
    ctx = _ctx(events)
    assert len(ctx.commands) == 1
    assert ctx.commands[0].first_token_hash == hash_token("ls")


def test_multiple_commands_get_inter_cmd_iats() -> None:
    events: list[AsciinemaEvent] = [
        (0.0, "i", "a"), (0.1, "i", "\r"),       # cmd "a" ends at 0.1
        (1.5, "i", "b"), (1.6, "i", "\r"),       # cmd "b" starts at 1.5, ends at 1.6
        (3.0, "i", "c"), (3.1, "i", "\r"),       # cmd "c" starts at 3.0
    ]
    ctx = _ctx(events)
    assert len(ctx.commands) == 3
    # IATs between command end and next command start
    assert ctx.inter_cmd_iats == (1.5 - 0.1, 3.0 - 1.6)


def test_output_per_cmd_counts_bytes_between_command_boundaries() -> None:
    events: list[AsciinemaEvent] = [
        (0.0, "i", "ls\r"),
        (0.1, "o", "file.txt\r\n"),     # 10 bytes
        (0.2, "o", "other.txt\r\n"),    # 11 bytes
        (1.0, "i", "ps\r"),
        (1.1, "o", "PID TTY\r\n"),      # 9 bytes (after cmd 2; tail beyond paired output)
    ]
    ctx = _ctx(events)
    assert len(ctx.commands) == 2
    # Pair is (cmd0.end_ts, cmd1.start_ts) = (0.0, 1.0); 21 bytes fall in
    assert ctx.output_per_cmd == (21,)


def test_first_token_only_hashes_first_word() -> None:
    events: list[AsciinemaEvent] = [(0.0, "i", "curl -sS https://target/\r")]
    ctx = _ctx(events)
    assert ctx.commands[0].first_token_hash == hash_token("curl")
    # Argument values are not stored anywhere in SessionContext
    assert "target" not in str(ctx.commands)


def test_blank_line_does_not_emit_command() -> None:
    # Hitting Enter on an empty prompt should not register a command
    events: list[AsciinemaEvent] = [(0.0, "i", "\r"), (0.5, "i", "ls\r")]
    ctx = _ctx(events)
    assert len(ctx.commands) == 1
    assert ctx.commands[0].first_token_hash == hash_token("ls")
