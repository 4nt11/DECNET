"""
Tests for templates/postgres/server.py

Covers the PostgreSQL startup / MD5-auth handshake happy path and regression
tests for zero/tiny/huge msg_len in both the startup and auth states.
"""

import importlib.util
import struct
import sys
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from .conftest import _FUZZ_SETTINGS, make_fake_decnet_logging, run_with_timeout


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_postgres():
    for key in list(sys.modules):
        if key in ("postgres_server", "decnet_logging"):
            del sys.modules[key]
    sys.modules["decnet_logging"] = make_fake_decnet_logging()
    spec = importlib.util.spec_from_file_location("postgres_server", "templates/postgres/server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_protocol(mod):
    proto = mod.PostgresProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    return proto, transport, written


def _startup_msg(user: str = "postgres", database: str = "postgres") -> bytes:
    """Build a valid PostgreSQL startup message."""
    params = f"user\x00{user}\x00database\x00{database}\x00\x00".encode()
    protocol = struct.pack(">I", 0x00030000)
    body = protocol + params
    msg_len = struct.pack(">I", 4 + len(body))
    return msg_len + body


def _ssl_request() -> bytes:
    return struct.pack(">II", 8, 80877103)


def _password_msg(password: str = "wrongpass") -> bytes:
    pw = password.encode() + b"\x00"
    return b"p" + struct.pack(">I", 4 + len(pw)) + pw


@pytest.fixture
def postgres_mod():
    return _load_postgres()


# ── Happy path ────────────────────────────────────────────────────────────────

def test_ssl_request_returns_N(postgres_mod):
    proto, _, written = _make_protocol(postgres_mod)
    proto.data_received(_ssl_request())
    assert b"N" in b"".join(written)


def test_startup_sends_auth_challenge(postgres_mod):
    proto, _, written = _make_protocol(postgres_mod)
    proto.data_received(_startup_msg())
    resp = b"".join(written)
    # AuthenticationMD5Password = 'R' + len(12) + type(5) + salt(4)
    assert resp[0:1] == b"R"


def test_startup_logs_username():
    mod = _load_postgres()
    log_mock = sys.modules["decnet_logging"]
    proto, _, _ = _make_protocol(mod)
    proto.data_received(_startup_msg(user="attacker"))
    log_mock.syslog_line.assert_called()
    calls_str = str(log_mock.syslog_line.call_args_list)
    assert "attacker" in calls_str


def test_state_becomes_auth_after_startup(postgres_mod):
    proto, _, _ = _make_protocol(postgres_mod)
    proto.data_received(_startup_msg())
    assert proto._state == "auth"


def test_password_triggers_close(postgres_mod):
    proto, transport, _ = _make_protocol(postgres_mod)
    proto.data_received(_startup_msg())
    transport.reset_mock()
    proto.data_received(_password_msg())
    transport.close.assert_called()


def test_partial_startup_waits(postgres_mod):
    proto, transport, _ = _make_protocol(postgres_mod)
    proto.data_received(b"\x00\x00\x00")  # only 3 bytes — not enough for msg_len
    transport.close.assert_not_called()
    assert proto._state == "startup"


def test_connection_lost_does_not_raise(postgres_mod):
    proto, _, _ = _make_protocol(postgres_mod)
    proto.connection_lost(None)


# ── Regression: startup state bad msg_len ────────────────────────────────────

def test_zero_msg_len_startup_closes(postgres_mod):
    proto, transport, _ = _make_protocol(postgres_mod)
    run_with_timeout(proto.data_received, b"\x00\x00\x00\x00")
    transport.close.assert_called()


def test_msg_len_4_startup_closes(postgres_mod):
    proto, transport, _ = _make_protocol(postgres_mod)
    # msg_len=4 means zero-byte body — too small for startup (needs protocol version)
    run_with_timeout(proto.data_received, struct.pack(">I", 4) + b"\x00" * 4)
    transport.close.assert_called()


def test_msg_len_7_startup_closes(postgres_mod):
    proto, transport, _ = _make_protocol(postgres_mod)
    run_with_timeout(proto.data_received, struct.pack(">I", 7) + b"\x00" * 7)
    transport.close.assert_called()


def test_huge_msg_len_startup_closes(postgres_mod):
    proto, transport, _ = _make_protocol(postgres_mod)
    run_with_timeout(proto.data_received, struct.pack(">I", 0x7FFFFFFF) + b"\x00" * 4)
    transport.close.assert_called()


# ── Regression: auth state bad msg_len ───────────────────────────────────────

def test_zero_msg_len_auth_closes(postgres_mod):
    proto, transport, _ = _make_protocol(postgres_mod)
    proto.data_received(_startup_msg())
    transport.reset_mock()
    # 'p' + msg_len=0
    run_with_timeout(proto.data_received, b"p" + struct.pack(">I", 0))
    transport.close.assert_called()


def test_msg_len_1_auth_closes(postgres_mod):
    proto, transport, _ = _make_protocol(postgres_mod)
    proto.data_received(_startup_msg())
    transport.reset_mock()
    run_with_timeout(proto.data_received, b"p" + struct.pack(">I", 1) + b"\x00" * 5)
    transport.close.assert_called()


def test_huge_msg_len_auth_closes(postgres_mod):
    proto, transport, _ = _make_protocol(postgres_mod)
    proto.data_received(_startup_msg())
    transport.reset_mock()
    run_with_timeout(proto.data_received, b"p" + struct.pack(">I", 0x7FFFFFFF) + b"\x00" * 5)
    transport.close.assert_called()


# ── Fuzz ──────────────────────────────────────────────────────────────────────

@pytest.mark.fuzz
@given(data=st.binary(min_size=0, max_size=512))
@settings(**_FUZZ_SETTINGS)
def test_fuzz_startup_state(data):
    mod = _load_postgres()
    proto, _, _ = _make_protocol(mod)
    run_with_timeout(proto.data_received, data)


@pytest.mark.fuzz
@given(data=st.binary(min_size=0, max_size=512))
@settings(**_FUZZ_SETTINGS)
def test_fuzz_auth_state(data):
    mod = _load_postgres()
    proto, _, _ = _make_protocol(mod)
    proto.data_received(_startup_msg())
    run_with_timeout(proto.data_received, data)
