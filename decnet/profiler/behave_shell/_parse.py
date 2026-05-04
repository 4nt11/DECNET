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
import re
from dataclasses import dataclass
from typing import Iterable, Iterator, Literal, Tuple

EventKind = Literal["i", "o"]
AsciinemaEvent = Tuple[float, EventKind, str]


# CSI / OSC / SGR / single-char escape sweeper. One pass, then we drop the
# stripped text on the floor — only the boolean error verdict (and the byte
# count, computed before stripping) leaves the helper. Full prompt-string
# parsing lives in Phase F.0; this is the slice cognitive.error_resilience.*
# needs to ship correctly.
_ANSI_RE = re.compile(
    r"""
    \x1B            # ESC
    (?:
        \[ [0-?]* [ -/]* [@-~]   # CSI
      | \] [^\x07\x1B]* (?:\x07|\x1B\\)?   # OSC, ST-or-BEL terminated
      | [@-Z\\-_]                # 2-byte escapes (ESC followed by 0x40-0x5F)
    )
    """,
    re.VERBOSE,
)


def strip_ansi(data: str) -> str:
    """Remove ANSI escape sequences. Used pre-error-pattern match."""
    return _ANSI_RE.sub("", data)


# Canonical bash/sh error fingerprints. v0.1 heuristic — Phase F.0's prompt
# parser will subsume this with PS1 + exit-code sniff. Any change here must
# leave the calibration grid green.
_OUTPUT_ERROR_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"command not found"),
    re.compile(r"No such file or directory"),
    re.compile(r"Permission denied"),
    re.compile(r": cannot "),
    re.compile(r"Operation not permitted"),
    re.compile(r"syntax error near unexpected token"),
)


def detect_error_in_output(stripped: str) -> bool:
    """True if any canonical error fingerprint matches the stripped output."""
    return any(p.search(stripped) for p in _OUTPUT_ERROR_PATTERNS)


@dataclass(frozen=True, slots=True)
class PasteBurst:
    """Contiguous run of paste-class input events."""

    start_ts: float
    end_ts: float
    char_count: int
    event_count: int


@dataclass(frozen=True, slots=True)
class PromptLine:
    """One PS1 prompt line detected in the output stream.

    PII trade-off (ANTI-authorised at Phase F): ``raw_line`` retains
    the ANSI-stripped text of the prompt — hostnames / usernames /
    cwd / etc. — because F.1 / F.3 / E.4 read off it. Capped at
    ``PROMPT_LINE_MAX_CHARS``. PromptLine instances live on
    ``SessionContext.prompt_lines``; only derived primitive values
    (``bash`` / ``en-US`` / ``present``) leave the engine.
    """

    ts: float
    suffix_char: str   # one of $ # % >
    raw_line: str      # ANSI stripped, capped at PROMPT_LINE_MAX_CHARS
    is_root: bool      # suffix_char == '#'


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

    ``errored`` (Step D.0) is set when the output stream between this
    command and the next contains a canonical bash/sh error fingerprint
    (see :func:`detect_error_in_output`). ``output_bytes`` is the byte
    count of that same window. Both are populated in the segmentation
    walk; the underlying output text is stripped of ANSI then matched,
    and the stripped text is discarded — only the bool and the int
    leave the segmentation pass. Drives the ``cognitive.error_resilience.*``
    family (Phase D) and the ``error_rate`` term of
    ``cognitive.cognitive_load``.
    """

    start_ts: float
    end_ts: float
    first_token_hash: str
    tab_count: int = 0
    shortcut_count: int = 0
    pipe_count: int = 0
    errored: bool = False
    output_bytes: int = 0
    followed_by_prompt: bool = False


def hash_token(token: str) -> str:
    """sha256-hex of a token; the only PII-safe handle on a command."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# Prompt-line detection (Step F.0). A prompt line ends with one of
# $/#/%/> followed by a space or end-of-line. The trailing space /
# newline is what tells us this is a *prompt* not just a sentence
# ending in those characters. We require either the space variant or
# the EOL variant to be present right after the suffix.
_PROMPT_LINE_RE = re.compile(
    r"""
    (?:^|\n)            # line start
    (?P<line>           # capture the prompt line itself
        [^\n]*?         # any line content (non-greedy)
        (?P<suffix>[$\#%>])   # prompt suffix
        \ ?             # optional trailing space (PS1 default has it)
    )
    (?=\n|\Z)           # at end of line / end of buffer
    """,
    re.VERBOSE,
)


def _detect_prompt_suffix(line: str) -> str | None:
    """Return the suffix character if ``line`` looks like a PS1 prompt.

    ``line`` is one logical output line, ANSI-stripped, trailing
    whitespace included. The discriminating shape: any text ending in
    one of ``$ # % >`` optionally followed by a single space. We require
    the line to be non-empty and the suffix to be the rightmost
    non-whitespace character.
    """
    stripped = line.rstrip()
    if not stripped:
        return None
    last = stripped[-1]
    return last if last in ("$", "#", "%", ">") else None


def extract_prompt_lines(
    text: str,
    *,
    base_ts: float,
    max_chars: int,
) -> Iterator[PromptLine]:
    """Yield prompt lines detected in ``text`` (already ANSI-stripped).

    All emitted prompts share ``base_ts`` — the caller is responsible
    for slicing output by event window before calling. A given output
    chunk yields **at most one prompt line** (the trailing one), but
    multi-line chunks containing multiple distinct prompts (mid-stream
    redraws) yield each. ``raw_line`` is capped at ``max_chars`` and
    leading/trailing whitespace stripped (preserving internal layout).
    """
    if not text:
        return
    for raw in text.split("\n"):
        suffix = _detect_prompt_suffix(raw)
        if suffix is None:
            continue
        line = raw.strip()
        if len(line) > max_chars:
            line = line[-max_chars:]
        yield PromptLine(
            ts=base_ts,
            suffix_char=suffix,
            raw_line=line,
            is_root=(suffix == "#"),
        )


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
