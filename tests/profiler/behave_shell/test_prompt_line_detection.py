# SPDX-License-Identifier: AGPL-3.0-or-later
"""Step F.0: prompt-line detector.

The detector is shared infrastructure (no primitive emit). These tests
pin ``PromptLine`` semantics + ``Command.followed_by_prompt`` directly
via ``build_session_context``. F.1 / F.3 / E.4 all depend on these
fields, so any drift here breaks four downstream primitives.
"""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._ctx import build_session_context
from decnet.profiler.behave_shell._parse import (
    AsciinemaEvent,
    PromptLine,
    extract_prompt_lines,
)


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


# ── extract_prompt_lines ────────────────────────────────────────────────────


def test_bash_prompt_detected() -> None:
    lines = list(extract_prompt_lines(
        "anti@host:~$ ", base_ts=1.0, max_chars=256,
    ))
    assert len(lines) == 1
    assert lines[0].suffix_char == "$"
    assert lines[0].is_root is False
    assert "anti@host" in lines[0].raw_line


def test_root_prompt_detected_as_root() -> None:
    lines = list(extract_prompt_lines(
        "root@host:/etc# ", base_ts=2.0, max_chars=256,
    ))
    assert len(lines) == 1
    assert lines[0].suffix_char == "#"
    assert lines[0].is_root is True


def test_zsh_prompt_detected() -> None:
    lines = list(extract_prompt_lines(
        "host% ", base_ts=3.0, max_chars=256,
    ))
    assert len(lines) == 1
    assert lines[0].suffix_char == "%"


def test_powershell_prompt_detected() -> None:
    lines = list(extract_prompt_lines(
        "PS C:\\Users\\anti> ", base_ts=4.0, max_chars=256,
    ))
    assert len(lines) == 1
    assert lines[0].suffix_char == ">"
    assert "PS " in lines[0].raw_line


def test_clean_output_no_prompt() -> None:
    lines = list(extract_prompt_lines(
        "file1\nfile2\nfile3\n", base_ts=5.0, max_chars=256,
    ))
    assert lines == []


def test_log_lines_ending_in_gt_are_not_prompts() -> None:
    """``dpkg.log`` style lines close with ``<none>`` — incidentally
    ending in ``>``. They must NOT register as fish prompts; otherwise
    a single ``cat /var/log/dpkg.log`` would flood ``shell_type`` votes
    and flip the mode for a plainly-bash session.
    """
    text = (
        "2026-05-09 02:18:09 configure libssl3:amd64 3.0.19-1~deb12u2 <none>\n"
        "2026-05-09 02:18:09 configure libexpat1:amd64 2.5.0-1+deb12u2 <none>\n"
        "2026-05-09 02:18:10 configure python3.11-minimal:amd64 3.11.2-6 <none>\n"
        "root@host:~# "
    )
    lines = list(extract_prompt_lines(text, base_ts=10.0, max_chars=256))
    assert len(lines) == 1
    assert lines[0].suffix_char == "#"


def test_output_line_ending_in_dollar_without_ps1_shape_rejected() -> None:
    """Sentence that happens to end in ``$`` (e.g. shell variable in
    a doc) without trailing space and without a PS1 shape token must
    not be treated as a prompt."""
    text = "use $PATH or $HOME\nset -- $\n"
    lines = list(extract_prompt_lines(text, base_ts=11.0, max_chars=256))
    assert lines == []


def test_long_prompt_capped_to_max_chars() -> None:
    long = "x" * 500 + "$ "
    lines = list(extract_prompt_lines(long, base_ts=6.0, max_chars=256))
    assert len(lines) == 1
    assert len(lines[0].raw_line) <= 256
    assert lines[0].suffix_char == "$"


def test_multi_line_output_with_trailing_prompt() -> None:
    """Mid-stream output then trailing prompt → one prompt detected."""
    text = "total 12\ndrwxr-xr-x  user  4096 May 4 .\nanti@host:~$ "
    lines = list(extract_prompt_lines(text, base_ts=7.0, max_chars=256))
    assert len(lines) == 1
    assert lines[0].suffix_char == "$"


def test_ansi_wrapped_prompt_detected_after_strip() -> None:
    """ANSI-coloured prompt → still detected (strip happens inside _output_window)."""
    events: list[AsciinemaEvent] = [
        *_typed("ls\r", t0=0.0),
        (0.20, "o", "file1\n"),
        (0.30, "o", "\x1b[1;32manti@host\x1b[0m:\x1b[34m~\x1b[0m$ "),
    ]
    ctx = build_session_context(events, sid="prompt-ansi", source="test")
    assert len(ctx.prompt_lines) == 1
    assert ctx.prompt_lines[0].suffix_char == "$"


# ── SessionContext.prompt_lines + Command.followed_by_prompt ────────────────


def test_no_output_no_prompts() -> None:
    events = _typed("ls\r", t0=0.0)
    ctx = build_session_context(events, sid="prompt-empty", source="test")
    assert ctx.prompt_lines == ()
    assert ctx.commands[0].followed_by_prompt is False


def test_command_followed_by_prompt_marks_field() -> None:
    events: list[AsciinemaEvent] = [
        *_typed("ls\r", t0=0.0),
        (0.20, "o", "file1\nanti@host:~$ "),
    ]
    ctx = build_session_context(events, sid="prompt-followed", source="test")
    assert ctx.commands[0].followed_by_prompt is True
    assert len(ctx.prompt_lines) == 1


def test_last_command_no_trailing_prompt() -> None:
    """Two commands, only the first has a trailing prompt."""
    events: list[AsciinemaEvent] = [
        *_typed("ls\r", t0=0.0),
        (0.20, "o", "file1\nanti@host:~$ "),
        *_typed("foo\r", t0=1.0),
        (1.20, "o", "bash: foo: command not found\n"),
    ]
    ctx = build_session_context(events, sid="prompt-mid", source="test")
    assert len(ctx.commands) == 2
    assert ctx.commands[0].followed_by_prompt is True
    assert ctx.commands[1].followed_by_prompt is False


# ── PII regression ──────────────────────────────────────────────────────────


def test_pii_prompt_text_does_not_leak_to_observations() -> None:
    """PromptLine.raw_line lives on ctx, never in observation JSON."""
    events: list[AsciinemaEvent] = [
        *_typed("ls\r", t0=0.0),
        (0.20, "o", "file1\nsecret-host-name@internal:~$ "),
    ]
    out = list(extract_session(events, sid="prompt-pii"))
    for obs in out:
        assert "secret-host-name" not in obs.model_dump_json()
