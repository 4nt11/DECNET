"""Asciinema event types + shard-line parsing helpers.

Shard lines are JSON objects ``{"sid": ..., "t": float, "ch": "i"|"o",
"d": str}`` produced by the DECNET PTY-recording wrapper and held in
sensor-side blob storage. The first line of each file is a header
(``{"sid": ..., "hdr": {...}}``) which carries no event payload — the
parser skips it.

The on-wire engine input is the simpler 3-tuple ``(t, kind, data)``
:data:`AsciinemaEvent`. Workers (``BEHAVE-INTEGRATION.md`` Phase 4)
either feed the 3-tuple directly or use :func:`parse_shard_line` to
turn a raw JSON string into one.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Iterator, Literal, Tuple

EventKind = Literal["i", "o"]
AsciinemaEvent = Tuple[float, EventKind, str]


@dataclass(frozen=True, slots=True)
class PasteBurst:
    """Contiguous run of paste-class input events.

    A paste-class event is a single input event whose ``data`` length
    is at least ``PASTE_MIN_CHARS_PER_EVENT`` — terminal pastes from
    xterm/kitty/iTerm arrive as one bulk write, so checking event size
    is the cheap-and-correct proxy for the bracketed-paste signal we
    don't get to see.

    Multiple consecutive paste-class events with low IATs collapse
    into one ``PasteBurst`` for higher-level reasoning (paste-rate /
    paste-style classification later).
    """

    start_ts: float
    end_ts: float
    char_count: int
    event_count: int


def parse_shard_line(line: str) -> AsciinemaEvent | None:
    """Turn one shard JSONL line into an :data:`AsciinemaEvent`.

    Returns ``None`` for the header line and for any line that is not
    a well-formed event record. Workers must filter ``None``s out
    before passing to :func:`extract_session`.
    """
    line = line.strip()
    if not line:
        return None
    try:
        rec = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(rec, dict):
        return None
    if "hdr" in rec or "t" not in rec or "ch" not in rec:
        return None
    t = rec.get("t")
    ch = rec.get("ch")
    d = rec.get("d", "")
    if not isinstance(t, (int, float)) or ch not in ("i", "o") or not isinstance(d, str):
        return None
    return (float(t), ch, d)


def parse_shard(lines: Iterable[str]) -> Iterator[AsciinemaEvent]:
    """Stream-parse a shard file's lines into events, skipping junk."""
    for line in lines:
        ev = parse_shard_line(line)
        if ev is not None:
            yield ev
