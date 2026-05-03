"""SessionContext: precomputed bundle every feature function reads from.

A naïve engine re-walks the event stream once per primitive. We don't
do that — one walk over the events builds this context, every feature
reads from it. Adding a new feature is O(1) cost on the parse side.

Step 1 fills ``iats`` (inter-key intervals between input events) and
``paste_bursts`` (contiguous runs of paste-class events). Step 4
will fill ``commands`` / ``inter_cmd_iats`` / ``output_per_cmd``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from decnet.profiler.behave_shell._parse import (
    AsciinemaEvent,
    Command,
    PasteBurst,
    hash_token,
)
from decnet.profiler.behave_shell._thresholds import (
    PASTE_BURST_MAX_IAT_S,
    PASTE_MIN_CHARS_PER_EVENT,
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


def _segment_commands(inputs: list[AsciinemaEvent]) -> tuple[Command, ...]:
    """Walk input events, splitting on ``\\r`` / ``\\n`` into commands.

    PII discipline: only the first whitespace-delimited token is
    retained, and only as a sha256 hash. Buffer contents are dropped
    on every command boundary; an unterminated trailing buffer (no
    final newline) yields no command.
    """
    cmds: list[Command] = []
    buf_chars: list[str] = []
    buf_start_ts: float | None = None

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
                    ))
                buf_chars = []
                buf_start_ts = None
            else:
                if not buf_chars:
                    buf_start_ts = t
                buf_chars.append(c)

    return tuple(cmds)


def _output_bytes_between(
    outputs: list[AsciinemaEvent],
    start: float,
    end: float,
) -> int:
    """Total ``len(d)`` of output events with ``start <= t < end``."""
    return sum(len(d) for t, _k, d in outputs if start <= t < end)


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
    commands = _segment_commands(inputs)
    inter_cmd_iats = tuple(
        max(0.0, commands[i + 1].start_ts - commands[i].end_ts)
        for i in range(len(commands) - 1)
    )
    output_per_cmd = tuple(
        _output_bytes_between(outputs, commands[i].end_ts, commands[i + 1].start_ts)
        for i in range(len(commands) - 1)
    )

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
    )
