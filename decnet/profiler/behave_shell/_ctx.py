"""SessionContext: precomputed bundle every feature function reads from.

A naïve engine re-walks the event stream once per primitive. We don't
do that — one walk over the events builds this context, every feature
reads from it. Adding a new feature is O(1) cost on the parse side.

Step 0 ships only the structural fields (sid / source / evidence_ref /
timing envelope). Step 1+ fills ``iats`` / ``paste_bursts`` /
``commands`` / ``inter_cmd_iats`` / ``output_per_cmd``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from decnet.profiler.behave_shell._parse import AsciinemaEvent


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


def build_session_context(
    events: Iterable[AsciinemaEvent],
    *,
    sid: str,
    source: str,
    evidence_ref: str | None = None,
) -> SessionContext:
    """Single-pass build of the SessionContext for ``events``.

    ``evidence_ref`` defaults to ``"session:" + sid`` so callers that
    don't yet plumb a real evidence pointer still get a stable,
    BEHAVE-envelope-valid string. Workers should pass an explicit
    pointer to the on-disk shard.
    """
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

    return SessionContext(
        sid=sid,
        source=source,
        evidence_ref=evidence_ref or f"session:{sid}",
        t_start=t_start,
        t_end=t_end,
        duration_s=max(0.0, t_end - t_start),
        input_events=tuple(inputs),
        output_events=tuple(outputs),
    )
