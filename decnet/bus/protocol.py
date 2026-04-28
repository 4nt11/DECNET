"""Wire protocol for the DECNET bus UNIX-socket transport.

Frame layout:

    <VERB> [<args ...>]\\n          # ASCII header, single line, no trailing space
    <4-byte big-endian body length>
    <body>                          # orjson-serialized dict, or empty (length 0)

Verbs:

* ``HELLO <client-name>`` — optional greeting, logged by server.  Body empty.
* ``PUB <topic>``          — publisher → server.  Body = payload dict.
* ``SUB <pattern>``        — subscriber → server.  Body empty.
* ``UNSUB <pattern>``      — subscriber → server.  Body empty.
* ``EVT <topic>``          — server → subscriber.  Body = payload dict (wrapped
                             in an :class:`~decnet.bus.base.Event` envelope).
* ``BYE``                  — either direction.  Body empty.  Graceful shutdown.

Parsing rules:

* The header is a single line terminated by ``\\n`` (LF).  ``\\r`` is tolerated
  but not required.
* Header tokens are whitespace-separated.  The first token is the verb;
  everything after is verb-specific.  We split on the first space only so
  topics / patterns with quoted content are not supported (they are not
  needed — topic segments forbid whitespace per :mod:`decnet.bus.topics`).
* Maximum header length is 4096 bytes; maximum body length is 1 MiB.  Beyond
  those, the connection is dropped with a logged error.  This is a honeypot
  framework, not a general-purpose message broker; a malformed frame is
  treated as hostile.
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from typing import Any

import orjson

MAX_HEADER_BYTES = 4096
MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB

# Verb constants (callers should reference these, not bare strings).
HELLO = "HELLO"
PUB = "PUB"
SUB = "SUB"
UNSUB = "UNSUB"
EVT = "EVT"
BYE = "BYE"

_VALID_VERBS = frozenset({HELLO, PUB, SUB, UNSUB, EVT, BYE})


class ProtocolError(Exception):
    """Malformed or oversized frame.  Callers should close the connection."""


@dataclass(frozen=True)
class Frame:
    """A parsed frame.  ``body`` is the raw (unparsed) body bytes — callers
    decide whether to orjson-decode it (the protocol does not know whether
    a given verb expects a dict body or an empty one).
    """

    verb: str
    args: str            # everything after the verb on the header line, trimmed
    body: bytes


def encode(verb: str, args: str = "", body: dict[str, Any] | None = None) -> bytes:
    """Serialize a frame.

    *body* is a dict that will be orjson-encoded, or ``None`` for an empty
    body.  The header line is written verbatim — callers must supply args
    that are free of ``\\n``.
    """
    if verb not in _VALID_VERBS:
        raise ProtocolError(f"unknown verb {verb!r}")
    if "\n" in args or "\r" in args:
        raise ProtocolError("args must not contain newline characters")

    body_bytes = b"" if body is None else orjson.dumps(body)
    if len(body_bytes) > MAX_BODY_BYTES:
        raise ProtocolError(
            f"body {len(body_bytes)} bytes exceeds max {MAX_BODY_BYTES}"
        )

    header = f"{verb} {args}".rstrip() + "\n"
    header_bytes = header.encode("ascii")
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise ProtocolError(
            f"header {len(header_bytes)} bytes exceeds max {MAX_HEADER_BYTES}"
        )
    return header_bytes + struct.pack(">I", len(body_bytes)) + body_bytes


async def read_frame(reader: asyncio.StreamReader) -> Frame | None:
    """Read one frame from *reader*.

    Returns ``None`` on clean EOF before a new frame starts.  Raises
    :class:`ProtocolError` on malformed input (caller should close the
    connection).
    """
    try:
        header = await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None
        raise ProtocolError("connection closed mid-header") from exc
    except asyncio.LimitOverrunError as exc:
        raise ProtocolError("header exceeded buffer limit") from exc

    if len(header) > MAX_HEADER_BYTES:
        raise ProtocolError(f"header {len(header)} bytes exceeds max")

    line = header.rstrip(b"\r\n").decode("ascii", errors="strict")
    if not line:
        raise ProtocolError("empty header line")

    verb, _, args = line.partition(" ")
    if verb not in _VALID_VERBS:
        raise ProtocolError(f"unknown verb {verb!r}")

    length_bytes = await reader.readexactly(4)
    (body_len,) = struct.unpack(">I", length_bytes)
    if body_len > MAX_BODY_BYTES:
        raise ProtocolError(f"body length {body_len} exceeds max")

    body = await reader.readexactly(body_len) if body_len else b""
    return Frame(verb=verb, args=args.strip(), body=body)


def decode_body(body: bytes) -> dict[str, Any]:
    """Decode a frame body as a JSON dict.  Empty body → empty dict."""
    if not body:
        return {}
    try:
        obj = orjson.loads(body)
    except orjson.JSONDecodeError as exc:
        raise ProtocolError(f"body is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ProtocolError(f"body must be a JSON object, got {type(obj).__name__}")
    return obj
