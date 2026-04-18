"""
Tests for templates/mssql/server.py

Covers the TDS pre-login / login7 happy path and regression tests for the
zero-length pkt_len infinite-loop bug that was fixed (pkt_len < 8 guard).
"""

import importlib.util
import struct
import sys
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from .conftest import _FUZZ_SETTINGS, make_fake_syslog_bridge, run_with_timeout


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_mssql():
    for key in list(sys.modules):
        if key in ("mssql_server", "syslog_bridge"):
            del sys.modules[key]
    sys.modules["syslog_bridge"] = make_fake_syslog_bridge()
    spec = importlib.util.spec_from_file_location("mssql_server", "templates/mssql/server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_protocol(mod):
    proto = mod.MSSQLProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    transport.is_closing.return_value = False
    proto.connection_made(transport)
    return proto, transport, written


def _tds_header(pkt_type: int, pkt_len: int) -> bytes:
    """Build an 8-byte TDS packet header."""
    return struct.pack(">BBHBBBB", pkt_type, 0x01, pkt_len, 0x00, 0x00, 0x01, 0x00)


def _prelogin_packet() -> bytes:
    header = _tds_header(0x12, 8)
    return header


def _login7_packet() -> bytes:
    """Minimal Login7 with 40-byte payload (username at offset 0, length 0)."""
    payload = b"\x00" * 40
    pkt_len = 8 + len(payload)
    header = _tds_header(0x10, pkt_len)
    return header + payload


@pytest.fixture
def mssql_mod():
    return _load_mssql()


# ── Happy path ────────────────────────────────────────────────────────────────

def test_prelogin_response_is_tds_type4(mssql_mod):
    proto, _, written = _make_protocol(mssql_mod)
    proto.data_received(_prelogin_packet())
    assert written, "expected a pre-login response"
    assert written[0][0] == 0x04


def test_prelogin_response_length_matches_header(mssql_mod):
    proto, _, written = _make_protocol(mssql_mod)
    proto.data_received(_prelogin_packet())
    resp = b"".join(written)
    declared_len = struct.unpack(">H", resp[2:4])[0]
    assert declared_len == len(resp)


def test_login7_auth_logged_and_closes(mssql_mod):
    proto, transport, written = _make_protocol(mssql_mod)
    proto.data_received(_prelogin_packet())
    written.clear()
    proto.data_received(_login7_packet())
    transport.close.assert_called()
    # error packet must be present
    assert any(b"\xaa" in chunk for chunk in written)


def test_partial_header_waits_for_more_data(mssql_mod):
    proto, transport, _ = _make_protocol(mssql_mod)
    proto.data_received(b"\x12\x01")
    transport.close.assert_not_called()


def test_connection_lost_does_not_raise(mssql_mod):
    proto, _, _ = _make_protocol(mssql_mod)
    proto.connection_lost(None)


# ── Regression: zero / small pkt_len ─────────────────────────────────────────

def test_zero_pkt_len_closes(mssql_mod):
    proto, transport, _ = _make_protocol(mssql_mod)
    # pkt_len = 0x0000 at bytes [2:4]
    data = b"\x12\x01\x00\x00\x00\x00\x01\x00"
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


def test_pkt_len_7_closes(mssql_mod):
    proto, transport, _ = _make_protocol(mssql_mod)
    # pkt_len = 7 (< 8 minimum)
    data = _tds_header(0x12, 7) + b"\x00"
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


def test_pkt_len_1_closes(mssql_mod):
    proto, transport, _ = _make_protocol(mssql_mod)
    data = _tds_header(0x12, 1) + b"\x00" * 7
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


# ── Fuzz ──────────────────────────────────────────────────────────────────────

@pytest.mark.fuzz
@given(data=st.binary(min_size=0, max_size=512))
@settings(**_FUZZ_SETTINGS)
def test_fuzz_arbitrary_bytes(data):
    mod = _load_mssql()
    proto, _, _ = _make_protocol(mod)
    run_with_timeout(proto.data_received, data)
