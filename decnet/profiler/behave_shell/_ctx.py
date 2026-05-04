"""SessionContext: precomputed bundle every feature function reads from.

A naïve engine re-walks the event stream once per primitive. We don't
do that — one walk over the events builds this context, every feature
reads from it. Adding a new feature is O(1) cost on the parse side.

Step 1 fills ``iats`` (inter-key intervals between input events) and
``paste_bursts`` (contiguous runs of paste-class events). Step 4
will fill ``commands`` / ``inter_cmd_iats`` / ``output_per_cmd``.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable

from decnet.profiler.behave_shell._parse import (
    AsciinemaEvent,
    Command,
    PasteBurst,
    detect_error_in_output,
    hash_token,
    strip_ansi,
)
from decnet.profiler.behave_shell._thresholds import (
    IKI_THINK_MAX_S,
    PASTE_BURST_MAX_IAT_S,
    PASTE_MIN_CHARS_PER_EVENT,
    SHORTCUT_CTRL_BYTES,
)


@dataclass(frozen=True, slots=True)
class SessionContext:
    sid: str
    source: str
    evidence_ref: str
    t_start: float
    t_end: float
    duration_s: float

    input_events: tuple[AsciinemaEvent, ...] = field(default_factory=tuple)
    output_events: tuple[AsciinemaEvent, ...] = field(default_factory=tuple)

    # Step 1 derivations
    iats: tuple[float, ...] = field(default_factory=tuple)
    paste_bursts: tuple[PasteBurst, ...] = field(default_factory=tuple)
    paste_event_count: int = 0

    # Step 4 derivations — command segmentation
    commands: tuple[Command, ...] = field(default_factory=tuple)
    inter_cmd_iats: tuple[float, ...] = field(default_factory=tuple)
    output_per_cmd: tuple[int, ...] = field(default_factory=tuple)

    # Step B.1 derivations — typing bursts (IATs split at think-pauses)
    typing_bursts: tuple[tuple[float, ...], ...] = field(default_factory=tuple)

    # Step B.3 derivations — error-correction signals
    backspace_count: int = 0
    backspace_iats: tuple[float, ...] = field(default_factory=tuple)
    kill_line_count: int = 0

    # Step B.4 derivations — per-command intra-typing IATs
    intra_command_iats: tuple[tuple[float, ...], ...] = field(default_factory=tuple)


def _detect_paste_bursts(
    inputs: list[AsciinemaEvent],
) -> tuple[tuple[PasteBurst, ...], int]:
    """Group consecutive paste-class input events into PasteBursts.

    A paste-class event is one with ``len(data) >= PASTE_MIN_CHARS_PER_EVENT``.
    Two adjacent paste-class events collapse into the same burst when
    their IAT is within ``PASTE_BURST_MAX_IAT_S``; otherwise a new
    burst opens. Returns the bursts and the total count of paste-class
    events (the same number ``BEHAVE`` prototype calls ``paste_events``).
    """
    bursts: list[PasteBurst] = []
    paste_count = 0

    cur_start: float | None = None
    cur_end: float = 0.0
    cur_chars: int = 0
    cur_events: int = 0
    last_t: float | None = None

    def _close() -> None:
        nonlocal cur_start, cur_end, cur_chars, cur_events
        if cur_start is not None and cur_events > 0:
            bursts.append(PasteBurst(
                start_ts=cur_start,
                end_ts=cur_end,
                char_count=cur_chars,
                event_count=cur_events,
            ))
        cur_start = None
        cur_end = 0.0
        cur_chars = 0
        cur_events = 0

    for t, _kind, data in inputs:
        is_paste = len(data) >= PASTE_MIN_CHARS_PER_EVENT
        if is_paste:
            paste_count += 1
            if cur_start is None or (
                last_t is not None and (t - last_t) > PASTE_BURST_MAX_IAT_S
            ):
                _close()
                cur_start = t
            cur_end = t
            cur_chars += len(data)
            cur_events += 1
        else:
            _close()
        last_t = t

    _close()
    return tuple(bursts), paste_count


_BACKSPACE_CHARS = ("\x7f", "\x08")
_KILL_LINE_CHARS = ("\x15", "\x17")


def _scan_correction_signals(
    inputs: list[AsciinemaEvent],
) -> tuple[int, tuple[float, ...], int]:
    """Walk input events char-by-char, count backspaces / kill-lines /
    timing IATs.

    PII discipline: only counts and IATs leave this function — no
    character data is retained or returned.
    """
    backspace_count = 0
    kill_line_count = 0
    iats: list[float] = []
    last_non_bs_t: float | None = None
    for t, _kind, data in inputs:
        for c in data:
            if c in _BACKSPACE_CHARS:
                backspace_count += 1
                if last_non_bs_t is not None:
                    iats.append(max(0.0, t - last_non_bs_t))
            elif c in _KILL_LINE_CHARS:
                kill_line_count += 1
                last_non_bs_t = t
            else:
                last_non_bs_t = t
    return backspace_count, tuple(iats), kill_line_count


def _split_typing_bursts(iats: tuple[float, ...]) -> tuple[tuple[float, ...], ...]:
    """Split a flat IAT sequence at gaps > IKI_THINK_MAX_S.

    Drops bursts of fewer than 3 IATs — too short to compute a stable
    CV. Mirrors BEHAVE prototype's ``_split_into_bursts``.
    """
    bursts: list[list[float]] = [[]]
    for x in iats:
        if x > IKI_THINK_MAX_S:
            if bursts[-1]:
                bursts.append([])
        else:
            bursts[-1].append(x)
    return tuple(tuple(b) for b in bursts if len(b) >= 3)


def _segment_commands(inputs: list[AsciinemaEvent]) -> tuple[Command, ...]:
    """Walk input events, splitting on ``\\r`` / ``\\n`` into commands.

    Retains only the first whitespace-delimited token as a sha256 hash
    plus three integer counters needed for the Phase C
    ``motor.shell_mastery.*`` primitives:

    * ``tab_count``      — ``\\t`` (0x09) keystrokes in the command
    * ``shortcut_count`` — readline control bytes from
      :data:`SHORTCUT_CTRL_BYTES`
    * ``pipe_count``     — ``|`` characters in the command (counted on
      every byte; pasted pipelines still indicate pipeline fluency the
      operator chose to execute)

    Buffer contents are dropped on every command boundary; an
    unterminated trailing buffer (no final newline) yields no command.
    """
    cmds: list[Command] = []
    buf_chars: list[str] = []
    buf_start_ts: float | None = None
    tab_count = 0
    shortcut_count = 0
    pipe_count = 0

    for t, _kind, data in inputs:
        for c in data:
            if c in ("\r", "\n"):
                if buf_chars:
                    text = "".join(buf_chars).strip()
                    first_token = text.split(maxsplit=1)[0] if text else ""
                    cmds.append(Command(
                        start_ts=buf_start_ts if buf_start_ts is not None else t,
                        end_ts=t,
                        first_token_hash=hash_token(first_token),
                        tab_count=tab_count,
                        shortcut_count=shortcut_count,
                        pipe_count=pipe_count,
                    ))
                buf_chars = []
                buf_start_ts = None
                tab_count = 0
                shortcut_count = 0
                pipe_count = 0
            else:
                if not buf_chars:
                    buf_start_ts = t
                buf_chars.append(c)
                if c == "\t":
                    tab_count += 1
                elif c == "|":
                    pipe_count += 1
                elif c in SHORTCUT_CTRL_BYTES:
                    shortcut_count += 1

    return tuple(cmds)


def _annotate_commands_with_output(
    commands: tuple[Command, ...],
    outputs: list[AsciinemaEvent],
) -> tuple[Command, ...]:
    """Re-emit ``commands`` with ``errored`` / ``output_bytes`` filled.

    The output window for ``commands[i]`` spans from its ``end_ts``
    (the ``\\r``/``\\n`` that ran it) to the ``start_ts`` of the next
    command. The last command's window is open-ended (``math.inf``)
    so output events arriving at or after ``t_end`` are still captured.
    """
    if not commands:
        return commands
    annotated: list[Command] = []
    for i, cmd in enumerate(commands):
        win_end = commands[i + 1].start_ts if i + 1 < len(commands) else math.inf
        byte_count, errored = _output_window(outputs, cmd.end_ts, win_end)
        annotated.append(Command(
            start_ts=cmd.start_ts,
            end_ts=cmd.end_ts,
            first_token_hash=cmd.first_token_hash,
            tab_count=cmd.tab_count,
            shortcut_count=cmd.shortcut_count,
            pipe_count=cmd.pipe_count,
            errored=errored,
            output_bytes=byte_count,
        ))
    return tuple(annotated)


def _per_command_iats(
    commands: tuple[Command, ...],
    inputs: list[AsciinemaEvent],
) -> tuple[tuple[float, ...], ...]:
    """Per-command IATs between consecutive input events whose
    timestamps fall in ``[cmd.start_ts, cmd.end_ts)``.

    Excludes the terminator IAT (the last event at ``cmd.end_ts`` is
    the ``\\r``/``\\n`` itself). Returns one tuple per command.
    """
    out: list[tuple[float, ...]] = []
    for cmd in commands:
        prev_t: float | None = None
        cmd_iats: list[float] = []
        for t, _kind, _data in inputs:
            if t < cmd.start_ts or t >= cmd.end_ts:
                continue
            if prev_t is not None:
                cmd_iats.append(max(0.0, t - prev_t))
            prev_t = t
        out.append(tuple(cmd_iats))
    return tuple(out)


def _output_bytes_between(
    outputs: list[AsciinemaEvent],
    start: float,
    end: float,
) -> int:
    """Total ``len(d)`` of output events with ``start <= t < end``."""
    return sum(len(d) for t, _k, d in outputs if start <= t < end)


def _output_window(
    outputs: list[AsciinemaEvent],
    start: float,
    end: float,
) -> tuple[int, bool]:
    """Walk output events in ``[start, end)`` once.

    Returns ``(byte_count, errored)``. ``byte_count`` is the raw byte
    count (pre-strip); ``errored`` is the canonical-error-pattern match
    over the ANSI-stripped concatenation. The stripped text is dropped
    on return — PII discipline: only an int and a bool leave this
    helper. The full output bytes never enter ``Command`` or the
    ``SessionContext``.
    """
    chunks: list[str] = []
    byte_count = 0
    for t, _k, d in outputs:
        if start <= t < end:
            byte_count += len(d)
            chunks.append(d)
    if not chunks:
        return 0, False
    stripped = strip_ansi("".join(chunks))
    return byte_count, detect_error_in_output(stripped)


def build_session_context(
    events: Iterable[AsciinemaEvent],
    *,
    sid: str,
    source: str,
    evidence_ref: str | None = None,
) -> SessionContext:
    """Single-pass build of the SessionContext for ``events``."""
    inputs: list[AsciinemaEvent] = []
    outputs: list[AsciinemaEvent] = []
    t_first: float | None = None
    t_last: float = 0.0

    for ev in events:
        t, kind, _ = ev
        if t_first is None:
            t_first = t
        if t > t_last:
            t_last = t
        if kind == "i":
            inputs.append(ev)
        elif kind == "o":
            outputs.append(ev)

    if t_first is None:
        t_start = 0.0
        t_end = 0.0
    else:
        t_start = t_first
        t_end = t_last

    iats: tuple[float, ...] = tuple(
        max(0.0, inputs[i][0] - inputs[i - 1][0]) for i in range(1, len(inputs))
    )
    paste_bursts, paste_count = _detect_paste_bursts(inputs)
    typing_bursts = _split_typing_bursts(iats)
    backspace_count, backspace_iats, kill_line_count = _scan_correction_signals(inputs)
    commands = _segment_commands(inputs)
    commands = _annotate_commands_with_output(commands, outputs)
    inter_cmd_iats = tuple(
        max(0.0, commands[i + 1].start_ts - commands[i].end_ts)
        for i in range(len(commands) - 1)
    )
    output_per_cmd = tuple(
        _output_bytes_between(outputs, commands[i].end_ts, commands[i + 1].start_ts)
        for i in range(len(commands) - 1)
    )
    intra_command_iats = _per_command_iats(commands, inputs)

    return SessionContext(
        sid=sid,
        source=source,
        evidence_ref=evidence_ref or f"session:{sid}",
        t_start=t_start,
        t_end=t_end,
        duration_s=max(0.0, t_end - t_start),
        input_events=tuple(inputs),
        output_events=tuple(outputs),
        iats=iats,
        paste_bursts=paste_bursts,
        paste_event_count=paste_count,
        commands=commands,
        inter_cmd_iats=inter_cmd_iats,
        output_per_cmd=output_per_cmd,
        typing_bursts=typing_bursts,
        backspace_count=backspace_count,
        backspace_iats=backspace_iats,
        kill_line_count=kill_line_count,
        intra_command_iats=intra_command_iats,
    )
