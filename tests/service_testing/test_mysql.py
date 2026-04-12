"""
Tests for templates/mysql/server.py

Covers the MySQL handshake happy path and regression tests for oversized
length fields that could cause huge buffer allocations.
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

def _load_mysql():
    for key in list(sys.modules):
        if key in ("mysql_server", "decnet_logging"):
            del sys.modules[key]
    sys.modules["decnet_logging"] = make_fake_decnet_logging()
    spec = importlib.util.spec_from_file_location("mysql_server", "templates/mysql/server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_protocol(mod):
    proto = mod.MySQLProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    written.clear()  # clear the greeting sent on connect
    return proto, transport, written


def _make_packet(payload: bytes, seq: int = 1) -> bytes:
    length = len(payload)
    return struct.pack("<I", length)[:3] + bytes([seq]) + payload


def _login_packet(username: str = "root") -> bytes:
    """Minimal MySQL client login packet."""
    caps = struct.pack("<I", 0x000FA685)
    max_pkt = struct.pack("<I", 16777216)
    charset = b"\x21"
    reserved = b"\x00" * 23
    uname = username.encode() + b"\x00"
    payload = caps + max_pkt + charset + reserved + uname
    return _make_packet(payload, seq=1)


@pytest.fixture
def mysql_mod():
    return _load_mysql()


# ── Happy path ────────────────────────────────────────────────────────────────

def test_connection_sends_greeting(mysql_mod):
    proto = mysql_mod.MySQLProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    greeting = b"".join(written)
    assert greeting[4] == 0x0a  # protocol v10
    assert b"mysql_native_password" in greeting


def test_login_packet_triggers_close(mysql_mod):
    proto, transport, _ = _make_protocol(mysql_mod)
    proto.data_received(_login_packet())
    transport.close.assert_called()


def test_login_packet_returns_access_denied(mysql_mod):
    proto, _, written = _make_protocol(mysql_mod)
    proto.data_received(_login_packet())
    resp = b"".join(written)
    assert b"\xff" in resp  # error packet marker


def test_login_logs_username():
    mod = _load_mysql()
    log_mock = sys.modules["decnet_logging"]
    proto, _, _ = _make_protocol(mod)
    proto.data_received(_login_packet(username="hacker"))
    calls_str = str(log_mock.syslog_line.call_args_list)
    assert "hacker" in calls_str


def test_empty_payload_packet_does_not_crash(mysql_mod):
    proto, transport, _ = _make_protocol(mysql_mod)
    proto.data_received(_make_packet(b"", seq=1))
    # Empty payload is silently skipped — no crash, no close
    transport.close.assert_not_called()


def test_partial_header_waits_for_more(mysql_mod):
    proto, transport, _ = _make_protocol(mysql_mod)
    proto.data_received(b"\x00\x00\x00")  # only 3 bytes — not enough
    transport.close.assert_not_called()


def test_connection_lost_does_not_raise(mysql_mod):
    proto, _, _ = _make_protocol(mysql_mod)
    proto.connection_lost(None)


# ── Regression: oversized length field ───────────────────────────────────────

def test_length_over_1mb_closes(mysql_mod):
    proto, transport, _ = _make_protocol(mysql_mod)
    # 1MB + 1 in 3-byte LE: 0x100001 → b'\x01\x00\x10'
    over_1mb = struct.pack("<I", 1024 * 1024 + 1)[:3]
    data = over_1mb + b"\x01"  # seq=1
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


def test_max_3byte_length_closes(mysql_mod):
    proto, transport, _ = _make_protocol(mysql_mod)
    # 0xFFFFFF = 16,777,215 — max representable in 3 bytes, clearly > 1MB cap
    data = b"\xff\xff\xff\x01"
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


def test_length_just_over_1mb_closes(mysql_mod):
    proto, transport, _ = _make_protocol(mysql_mod)
    # 1MB + 1 byte — just over the cap
    just_over = struct.pack("<I", 1024 * 1024 + 1)[:3]
    data = just_over + b"\x01"
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


# ── Fuzz ──────────────────────────────────────────────────────────────────────

@pytest.mark.fuzz
@given(data=st.binary(min_size=0, max_size=512))
@settings(**_FUZZ_SETTINGS)
def test_fuzz_arbitrary_bytes(data):
    mod = _load_mysql()
    proto, _, _ = _make_protocol(mod)
    run_with_timeout(proto.data_received, data)
