"""Step D.0: per-command error-signal helper.

The helper is infrastructure (no primitive emit) — these tests pin
``Command.errored`` and ``Command.output_bytes`` semantics directly via
``build_session_context``. The Phase D primitives (D.1, D.5–D.7) all
read the same fields, so any drift here breaks four downstream
primitives at once.
"""
from __future__ import annotations

from decnet.profiler.behave_shell import extract_session
from decnet.profiler.behave_shell._ctx import build_session_context
from decnet.profiler.behave_shell._parse import (
    AsciinemaEvent,
    detect_error_in_output,
    strip_ansi,
)


def _typed(text: str, t0: float = 0.0, dt: float = 0.05) -> list[AsciinemaEvent]:
    return [(t0 + i * dt, "i", c) for i, c in enumerate(text)]


# ── strip_ansi ──────────────────────────────────────────────────────────────


def test_strip_ansi_removes_csi_sgr() -> None:
    assert strip_ansi("\x1b[31mPermission denied\x1b[0m") == "Permission denied"


def test_strip_ansi_removes_osc_with_bel() -> None:
    # OSC: ESC ] ... BEL — terminal title escape
    assert strip_ansi("\x1b]0;title\x07hello") == "hello"


def test_strip_ansi_passthrough_clean_text() -> None:
    assert strip_ansi("plain output\nwith newline") == "plain output\nwith newline"


# ── detect_error_in_output ──────────────────────────────────────────────────


def test_detect_error_command_not_found() -> None:
    assert detect_error_in_output("bash: foo: command not found") is True


def test_detect_error_no_such_file() -> None:
    assert detect_error_in_output("ls: /nope: No such file or directory") is True


def test_detect_error_permission_denied() -> None:
    assert detect_error_in_output("cat: /etc/shadow: Permission denied") is True


def test_detect_error_cannot_access() -> None:
    assert detect_error_in_output("ls: cannot access '/x': No such file") is True


def test_detect_error_clean_output() -> None:
    assert detect_error_in_output("total 12\ndrwxr-xr-x  3 user user 4096 May  3 12:00 .") is False


# ── Command.errored / output_bytes wired through build_session_context ──────


def test_command_clean_output_not_errored() -> None:
    events: list[AsciinemaEvent] = [
        *_typed("ls\r"),
        (0.20, "o", "file1\nfile2\n"),
    ]
    ctx = build_session_context(events, sid="d0-clean", source="test")
    assert len(ctx.commands) == 1
    assert ctx.commands[0].errored is False
    assert ctx.commands[0].output_bytes == len("file1\nfile2\n")


def test_command_with_error_pattern_marked_errored() -> None:
    events: list[AsciinemaEvent] = [
        *_typed("foo\r"),
        (0.20, "o", "bash: foo: command not found\n"),
    ]
    ctx = build_session_context(events, sid="d0-err", source="test")
    assert ctx.commands[0].errored is True
    assert ctx.commands[0].output_bytes == len("bash: foo: command not found\n")


def test_command_with_ansi_wrapped_error_marked_errored() -> None:
    """ANSI strip must run before pattern match (red-coloured `Permission denied`)."""
    events: list[AsciinemaEvent] = [
        *_typed("cat /etc/shadow\r"),
        (1.50, "o", "\x1b[31mcat: /etc/shadow: Permission denied\x1b[0m\n"),
    ]
    ctx = build_session_context(events, sid="d0-ansi", source="test")
    assert ctx.commands[0].errored is True


def test_last_command_output_window_extends_to_t_end() -> None:
    """The last command's window has no ``commands[i+1]`` — it spans to t_end."""
    events: list[AsciinemaEvent] = [
        *_typed("ls\r", t0=0.0),
        *_typed("foo\r", t0=1.0),
        (1.50, "o", "bash: foo: command not found\n"),
    ]
    ctx = build_session_context(events, sid="d0-last", source="test")
    assert len(ctx.commands) == 2
    assert ctx.commands[0].errored is False
    assert ctx.commands[1].errored is True


def test_no_output_events_no_errored() -> None:
    """A shard with no ``'o'`` events emits clean ``errored=False`` per command."""
    events: list[AsciinemaEvent] = _typed("ls\r")
    ctx = build_session_context(events, sid="d0-noout", source="test")
    assert ctx.commands[0].errored is False
    assert ctx.commands[0].output_bytes == 0


# ── PII regression ──────────────────────────────────────────────────────────


def test_pii_no_output_bodies_in_observations() -> None:
    """Output bytes containing operator-identifying strings must not leak.

    The error pattern triggers ``errored=True``; the surrounding output
    contains the literal ``secret_payload_xyz`` token. No observation may
    serialise that token, since the engine only retains a bool + an int.
    """
    events: list[AsciinemaEvent] = [
        *_typed("foo\r"),
        (0.20, "o", "secret_payload_xyz\nbash: foo: command not found\n"),
    ]
    out = list(extract_session(events, sid="d0-pii"))
    for obs in out:
        assert "secret_payload_xyz" not in obs.model_dump_json()
