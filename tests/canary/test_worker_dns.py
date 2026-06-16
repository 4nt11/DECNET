# SPDX-License-Identifier: AGPL-3.0-or-later
"""DNS surface coverage for the canary worker.

We don't open a real UDP socket — instead we drive
:class:`CanaryDNSProtocol` directly with synthesised packets and
inspect the bytes it returns via a fake transport.  Faster than a
real listener, and avoids needing privileged ports in the test
runner.
"""
from __future__ import annotations

import asyncio
import struct
from typing import AsyncIterator

import pytest
import pytest_asyncio

from decnet.canary.dns_server import (
    CanaryDNSProtocol,
    _encode_name,
    parse_query,
)


def _build_query(qname: str, txid: int = 0xCAFE, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD bit set
    return header + _encode_name(qname) + struct.pack("!HH", qtype, 1)


class _FakeTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple]] = []

    def sendto(self, data: bytes, addr: tuple) -> None:
        self.sent.append((data, addr))


@pytest_asyncio.fixture
async def proto_and_hits():
    hits: list[tuple[str, str, str]] = []

    async def hook(slug: str, query, src_ip: str) -> None:  # type: ignore[no-untyped-def]
        hits.append((slug, query.qname, src_ip))

    proto = CanaryDNSProtocol("canary.example.test", hook, answer_ip="192.0.2.1")
    transport = _FakeTransport()
    proto.connection_made(transport)
    yield proto, transport, hits


@pytest.mark.asyncio
async def test_known_slug_returns_answer_and_fires_hook(proto_and_hits) -> None:
    proto, transport, hits = proto_and_hits
    pkt = _build_query("slug42.canary.example.test")
    proto.datagram_received(pkt, ("203.0.113.7", 12345))
    # Allow the create_task hook to settle.
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert hits == [("slug42", "slug42.canary.example.test", "203.0.113.7")]
    assert len(transport.sent) == 1
    response = transport.sent[0][0]
    # Header: ANCOUNT == 1, RCODE == 0 in lower 4 bits of flags[1].
    _txid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", response[:12])
    assert (flags & 0x0F) == 0  # NOERROR
    assert an == 1


@pytest.mark.asyncio
async def test_unknown_slug_returns_nxdomain(proto_and_hits) -> None:
    proto, transport, hits = proto_and_hits
    pkt = _build_query("not-our-zone.example.com")
    proto.datagram_received(pkt, ("203.0.113.7", 12345))
    await asyncio.sleep(0)
    assert hits == []
    assert len(transport.sent) == 1
    response = transport.sent[0][0]
    _txid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", response[:12])
    assert (flags & 0x0F) == 3  # NXDOMAIN
    assert an == 0


@pytest.mark.asyncio
async def test_multi_label_subdomain_is_ignored(proto_and_hits) -> None:
    """Slug must be exactly one label.  ``foo.bar.canary.example.test``
    is an attacker probing a sub-resource we don't model — NXDOMAIN."""
    proto, transport, hits = proto_and_hits
    pkt = _build_query("foo.bar.canary.example.test")
    proto.datagram_received(pkt, ("203.0.113.7", 12345))
    await asyncio.sleep(0)
    assert hits == []


@pytest.mark.asyncio
async def test_malformed_packet_is_dropped_silently(proto_and_hits) -> None:
    proto, transport, hits = proto_and_hits
    proto.datagram_received(b"\x00\x01\x02", ("203.0.113.7", 12345))
    await asyncio.sleep(0)
    assert hits == []
    assert transport.sent == []


def test_parse_query_round_trip() -> None:
    pkt = _build_query("abc.def.canary.example.test", txid=0x1234, qtype=1)
    q = parse_query(pkt)
    assert q.txid == 0x1234
    assert q.qname == "abc.def.canary.example.test"
    assert q.qtype == 1
    assert q.qclass == 1


def test_parse_query_handles_pointer_loop() -> None:
    """Malicious packet with a pointer loop must raise, not hang."""
    # Header (12) + name with a self-pointer at offset 12.
    header = struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0)
    name = struct.pack("!H", 0xC00C)  # pointer back to offset 12
    qtype_qclass = struct.pack("!HH", 1, 1)
    packet = header + name + qtype_qclass
    with pytest.raises(ValueError, match="pointer loop"):
        parse_query(packet)
