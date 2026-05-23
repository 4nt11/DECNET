# SPDX-License-Identifier: AGPL-3.0-or-later
"""Minimal authoritative DNS server for canary tokens (stdlib only).

We don't need a full resolver — only enough to:

1. Decode an inbound query's qname.
2. If the qname matches ``<slug>.<canary_zone>``, log the callback,
   publish ``canary.<token_id>.triggered`` on the bus, and return a
   plausible A record (any RFC-5737 reserved address would do; we
   use 192.0.2.1) so the attacker's resolver doesn't loop on
   NXDOMAIN.
3. For unknown qnames return NXDOMAIN.

DNS-over-UDP wire format is well-trodden: 12-byte header + name
labels + qtype + qclass.  We implement just the bits we need.

This module deliberately avoids the ``dnslib`` PyPI package so the
canary worker has no extra dependency surface.  If we ever need
EDNS0, DNSSEC, or other niceties we'll swap to dnslib then.
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional, Tuple


@dataclass(frozen=True)
class DNSQuery:
    """Decoded query — only the bits the canary worker cares about."""

    txid: int
    qname: str  # lowercase, no trailing dot
    qtype: int
    qclass: int
    flags: int


def _decode_name(buf: bytes, offset: int) -> Tuple[str, int]:
    """Return ``(qname_lowercase_no_dot, bytes_consumed)``.

    Supports compressed pointers (RFC 1035 §4.1.4).  Doesn't recurse —
    we walk the pointer chain iteratively with a hop cap to avoid
    pointer-loop DoS.
    """
    labels: list[str] = []
    pos = offset
    consumed = 0
    jumped = False
    hops = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated DNS name")
        length = buf[pos]
        if length == 0:
            pos += 1
            if not jumped:
                consumed = pos - offset
            break
        if (length & 0xC0) == 0xC0:
            # Compression pointer.
            if pos + 1 >= len(buf):
                raise ValueError("truncated DNS pointer")
            ptr = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                consumed = (pos + 2) - offset
            pos = ptr
            jumped = True
            hops += 1
            if hops > 10:
                raise ValueError("DNS pointer loop")
            continue
        pos += 1
        if pos + length > len(buf):
            raise ValueError("truncated DNS label")
        labels.append(buf[pos:pos + length].decode("ascii", "replace"))
        pos += length
    return ".".join(labels).lower(), consumed


def parse_query(packet: bytes) -> DNSQuery:
    """Parse the (single) question of a DNS query packet."""
    if len(packet) < 12:
        raise ValueError("DNS packet too short")
    txid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", packet[:12]
    )
    if qdcount != 1:
        raise ValueError(f"expected 1 question, got {qdcount}")
    qname, consumed = _decode_name(packet, 12)
    pos = 12 + consumed
    if pos + 4 > len(packet):
        raise ValueError("truncated DNS qtype/qclass")
    qtype, qclass = struct.unpack("!HH", packet[pos:pos + 4])
    return DNSQuery(
        txid=txid, qname=qname, qtype=qtype, qclass=qclass, flags=flags,
    )


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        b = label.encode("ascii", "replace")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _build_response(
    query: DNSQuery,
    *,
    rcode: int = 0,
    answer_ip: Optional[str] = None,
) -> bytes:
    """Encode a DNS response packet.

    *rcode* 0 = NOERROR, 3 = NXDOMAIN.  When *answer_ip* is supplied
    and the query was for an A record we include exactly one answer
    (TTL 60, class IN).
    """
    qd_count = 1
    an_count = 1 if (answer_ip and query.qtype == 1 and rcode == 0) else 0
    flags = 0x8400 | rcode  # response + authoritative + RA bit clear + rcode
    header = struct.pack(
        "!HHHHHH", query.txid, flags, qd_count, an_count, 0, 0,
    )
    qname_bytes = _encode_name(query.qname)
    question = qname_bytes + struct.pack("!HH", query.qtype, query.qclass)

    answer = b""
    if an_count and answer_ip is not None:
        # Use a name pointer back to the question (offset 12).
        ptr = struct.pack("!H", 0xC000 | 12)
        rdata = bytes(int(o) for o in answer_ip.split("."))
        answer = ptr + struct.pack("!HHIH", 1, 1, 60, 4) + rdata

    return header + question + answer


# Hook signature: receives the matched slug + the query; returns
# nothing.  The worker uses it to persist a CanaryTrigger row and
# publish the bus event.
TriggerHook = Callable[[str, DNSQuery, str], Awaitable[None]]


class CanaryDNSProtocol(asyncio.DatagramProtocol):
    """asyncio UDP server endpoint for canary DNS callbacks.

    Constructor takes the canary zone (``"canary.example.test"``) and
    a coroutine called when a query matches ``<slug>.<zone>``.  The
    hook runs in the event loop's task; we don't block the receive
    path on it.
    """

    def __init__(
        self,
        zone: str,
        hook: TriggerHook,
        *,
        answer_ip: str = "192.0.2.1",
    ) -> None:
        # Normalise: lowercase, no leading/trailing dot.
        self._zone = zone.lower().strip(".")
        self._suffix = "." + self._zone if self._zone else ""
        self._hook = hook
        self._answer_ip = answer_ip
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport) -> None:
        self._transport = transport

    def datagram_received(
        self, data: bytes, addr: Tuple[str, int],
    ) -> None:
        try:
            query = parse_query(data)
        except ValueError:
            # Malformed query — drop silently.  Returning a FORMERR
            # would tip off the attacker that *something* is listening
            # on this port; the stealth posture (feedback_stealth)
            # prefers radio silence on parse errors.
            return
        slug = self._slug_for(query.qname)
        if slug is None:
            # Unknown name — NXDOMAIN.
            self._send(addr, _build_response(query, rcode=3))
            return
        # Known name — answer with our sinkhole IP, then fire the hook.
        self._send(addr, _build_response(query, answer_ip=self._answer_ip))
        asyncio.ensure_future(self._hook(slug, query, addr[0]))

    def _slug_for(self, qname: str) -> Optional[str]:
        if not self._zone or not qname.endswith(self._suffix):
            return None
        slug = qname[: -len(self._suffix)]
        # Single-label slug only; multi-label means the attacker is
        # querying a sub-resource we don't model.
        if not slug or "." in slug:
            return None
        return slug

    def _send(self, addr: Tuple[str, int], packet: bytes) -> None:
        if self._transport is not None:
            self._transport.sendto(packet, addr)
