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

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Iterator, Literal, Tuple

EventKind = Literal["i", "o"]
AsciinemaEvent = Tuple[float, EventKind, str]


@dataclass(frozen=True, slots=True)
class PasteBurst:
    """Contiguous run of paste-class input events."""

    start_ts: float
    end_ts: float
    char_count: int
    event_count: int


@dataclass(frozen=True, slots=True)
class Command:
    """One command-line invocation, segmented from the input stream.

    PII discipline (per ``BEHAVE-INTEGRATION.md`` and the BEHAVE
    envelope's pinned policy): only the *first token* of the command
    is retained, and only as a sha256 hash. The full command body
    never enters the engine's data structures, never goes to the bus,
    never ends up in the database. ``first_token_hash`` lets
    cognitive.command_branch_diversity (Step 6) count distinct
    invocations without learning anything about argument values.

    ``end_ts`` is the timestamp of the ``\\r`` / ``\\n`` that
    terminated the command; ``start_ts`` is the first character typed
    or pasted into it.

    ``tab_count`` / ``shortcut_count`` / ``pipe_count`` are integer
    counters populated by the context builder during the per-command
    byte sweep. They feed the ``motor.shell_mastery.*`` primitives
    (Phase C). The raw bytes themselves are read once during the
    sweep and discarded — only the counters are retained.
    """

    start_ts: float
    end_ts: float
    first_token_hash: str
    tab_count: int = 0
    shortcut_count: int = 0
    pipe_count: int = 0


def hash_token(token: str) -> str:
    """sha256-hex of a token; the only PII-safe handle on a command."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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
