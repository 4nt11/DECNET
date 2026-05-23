# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the wire protocol framing."""
from __future__ import annotations

import asyncio
import struct

import pytest

from decnet.bus import protocol


def _reader_from(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


async def _read_one(data: bytes) -> protocol.Frame | None:
    return await protocol.read_frame(_reader_from(data))


class TestEncodeDecode:
    async def test_pub_round_trip(self) -> None:
        data = protocol.encode(protocol.PUB, args="topology.abc.status", body={"payload": {"x": 1}})
        frame = await _read_one(data)
        assert frame is not None
        assert frame.verb == protocol.PUB
        assert frame.args == "topology.abc.status"
        assert protocol.decode_body(frame.body) == {"payload": {"x": 1}}

    async def test_sub_empty_body(self) -> None:
        data = protocol.encode(protocol.SUB, args="topology.*.mutation.*")
        frame = await _read_one(data)
        assert frame is not None
        assert frame.verb == protocol.SUB
        assert frame.args == "topology.*.mutation.*"
        assert frame.body == b""

    async def test_bye_no_args(self) -> None:
        data = protocol.encode(protocol.BYE)
        frame = await _read_one(data)
        assert frame is not None
        assert frame.verb == protocol.BYE
        assert frame.args == ""
        assert frame.body == b""

    async def test_clean_eof_returns_none(self) -> None:
        assert await _read_one(b"") is None


class TestProtocolErrors:
    def test_encode_rejects_unknown_verb(self) -> None:
        with pytest.raises(protocol.ProtocolError):
            protocol.encode("NOPE", args="x")

    def test_encode_rejects_newline_in_args(self) -> None:
        with pytest.raises(protocol.ProtocolError):
            protocol.encode(protocol.PUB, args="bad\ntopic")

    def test_encode_rejects_oversized_body(self) -> None:
        big = {"payload": {"x": "a" * (protocol.MAX_BODY_BYTES + 1)}}
        with pytest.raises(protocol.ProtocolError):
            protocol.encode(protocol.PUB, args="t", body=big)

    async def test_decode_rejects_unknown_verb(self) -> None:
        bad = b"NOPE x\n" + struct.pack(">I", 0)
        with pytest.raises(protocol.ProtocolError):
            await _read_one(bad)

    async def test_decode_rejects_oversized_body_length(self) -> None:
        bad = b"PUB x\n" + struct.pack(">I", protocol.MAX_BODY_BYTES + 1)
        with pytest.raises(protocol.ProtocolError):
            await _read_one(bad)

    async def test_decode_rejects_truncated_body(self) -> None:
        bad = b"PUB x\n" + struct.pack(">I", 10) + b"short"
        with pytest.raises(Exception):  # IncompleteReadError bubbles up
            await _read_one(bad)

    def test_decode_body_rejects_non_object(self) -> None:
        import orjson
        with pytest.raises(protocol.ProtocolError):
            protocol.decode_body(orjson.dumps([1, 2, 3]))

    def test_decode_body_empty_returns_empty_dict(self) -> None:
        assert protocol.decode_body(b"") == {}
