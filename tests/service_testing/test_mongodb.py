"""
Tests for templates/mongodb/server.py

Covers the MongoDB wire-protocol (OP_MSG / OP_QUERY) happy path and regression
tests for the zero-length msg_len infinite-loop bug and oversized msg_len.
"""

import importlib.util
import struct
import sys
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from .conftest import _FUZZ_SETTINGS, make_fake_decnet_logging, run_with_timeout


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_mongodb():
    for key in list(sys.modules):
        if key in ("mongodb_server", "decnet_logging"):
            del sys.modules[key]
    sys.modules["decnet_logging"] = make_fake_decnet_logging()
    spec = importlib.util.spec_from_file_location("mongodb_server", "templates/mongodb/server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_protocol(mod):
    proto = mod.MongoDBProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    return proto, transport, written


def _minimal_bson() -> bytes:
    return b"\x05\x00\x00\x00\x00"  # empty document


def _op_msg_packet(request_id: int = 1) -> bytes:
    """Build a valid OP_MSG with an empty BSON body."""
    flag_bits = struct.pack("<I", 0)
    section = b"\x00" + _minimal_bson()
    body = flag_bits + section
    total = 16 + len(body)
    header = struct.pack("<iiii", total, request_id, 0, 2013)
    return header + body


def _op_query_packet(request_id: int = 2) -> bytes:
    """Build a minimal OP_QUERY."""
    flags = struct.pack("<I", 0)
    coll = b"admin.$cmd\x00"
    skip = struct.pack("<I", 0)
    ret = struct.pack("<I", 1)
    query = _minimal_bson()
    body = flags + coll + skip + ret + query
    total = 16 + len(body)
    header = struct.pack("<iiii", total, request_id, 0, 2004)
    return header + body


@pytest.fixture
def mongodb_mod():
    return _load_mongodb()


# ── Happy path ────────────────────────────────────────────────────────────────

def test_op_msg_returns_response(mongodb_mod):
    proto, _, written = _make_protocol(mongodb_mod)
    proto.data_received(_op_msg_packet())
    assert written, "expected a response to OP_MSG"


def test_op_msg_response_opcode_is_2013(mongodb_mod):
    proto, _, written = _make_protocol(mongodb_mod)
    proto.data_received(_op_msg_packet())
    resp = b"".join(written)
    assert len(resp) >= 16
    opcode = struct.unpack("<i", resp[12:16])[0]
    assert opcode == 2013


def test_op_query_returns_op_reply(mongodb_mod):
    proto, _, written = _make_protocol(mongodb_mod)
    proto.data_received(_op_query_packet())
    resp = b"".join(written)
    assert len(resp) >= 16
    opcode = struct.unpack("<i", resp[12:16])[0]
    assert opcode == 1


def test_partial_header_waits_for_more_data(mongodb_mod):
    proto, transport, _ = _make_protocol(mongodb_mod)
    proto.data_received(b"\x1a\x00\x00\x00")  # only 4 bytes (< 16)
    transport.close.assert_not_called()


def test_two_consecutive_messages(mongodb_mod):
    proto, _, written = _make_protocol(mongodb_mod)
    two = _op_msg_packet(1) + _op_msg_packet(2)
    proto.data_received(two)
    assert len(written) >= 2


def test_connection_lost_does_not_raise(mongodb_mod):
    proto, _, _ = _make_protocol(mongodb_mod)
    proto.connection_lost(None)


# ── Regression: malformed msg_len ────────────────────────────────────────────

def test_zero_msg_len_closes(mongodb_mod):
    proto, transport, _ = _make_protocol(mongodb_mod)
    # msg_len = 0 at bytes [0:4] LE — buffer has 16 bytes so outer while triggers
    data = b"\x00\x00\x00\x00" + b"\x00" * 12
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


def test_msg_len_15_closes(mongodb_mod):
    proto, transport, _ = _make_protocol(mongodb_mod)
    # msg_len = 15 (below 16-byte wire-protocol minimum)
    data = struct.pack("<I", 15) + b"\x00" * 12
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


def test_msg_len_over_48mb_closes(mongodb_mod):
    proto, transport, _ = _make_protocol(mongodb_mod)
    # msg_len = 48MB + 1
    big = 48 * 1024 * 1024 + 1
    data = struct.pack("<I", big) + b"\x00" * 12
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


def test_msg_len_exactly_48mb_plus1_closes(mongodb_mod):
    proto, transport, _ = _make_protocol(mongodb_mod)
    # cap is strictly > 48MB, so 48MB+1 must close
    data = struct.pack("<I", 48 * 1024 * 1024 + 1) + b"\x00" * 12
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


# ── Fuzz ──────────────────────────────────────────────────────────────────────

@pytest.mark.fuzz
@given(data=st.binary(min_size=0, max_size=512))
@settings(**_FUZZ_SETTINGS)
def test_fuzz_arbitrary_bytes(data):
    mod = _load_mongodb()
    proto, _, _ = _make_protocol(mod)
    run_with_timeout(proto.data_received, data)
