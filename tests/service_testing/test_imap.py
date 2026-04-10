"""
Tests for templates/imap/server.py

Exercises IMAP state machine, auth, and negative tests.
"""

import importlib.util
import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest


def _make_fake_decnet_logging() -> ModuleType:
    mod = ModuleType("decnet_logging")
    mod.syslog_line = MagicMock(return_value="")
    mod.write_syslog_file = MagicMock()
    mod.forward_syslog = MagicMock()
    mod.SEVERITY_WARNING = 4
    mod.SEVERITY_INFO = 6
    return mod

def _load_imap():
    env = {
        "NODE_NAME": "testhost",
        "IMAP_USERS": "admin:admin123,root:toor",
        "IMAP_BANNER": "* OK [testhost] Dovecot ready."
    }
    for key in list(sys.modules):
        if key in ("imap_server", "decnet_logging"):
            del sys.modules[key]

    sys.modules["decnet_logging"] = _make_fake_decnet_logging()

    spec = importlib.util.spec_from_file_location("imap_server", "templates/imap/server.py")
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", env, clear=False):
        spec.loader.exec_module(mod)
    return mod

def _make_protocol(mod):
    proto = mod.IMAPProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    written.clear()
    return proto, transport, written

def _send(proto, data: str) -> None:
    proto.data_received(data.encode() + b"\r\n")

@pytest.fixture
def imap_mod():
    return _load_imap()

def test_imap_login_success(imap_mod):
    proto, transport, written = _make_protocol(imap_mod)
    _send(proto, 'A1 LOGIN admin admin123')
    assert b"A1 OK" in b"".join(written)
    assert proto._state == "AUTHENTICATED"

def test_imap_login_fail(imap_mod):
    proto, transport, written = _make_protocol(imap_mod)
    _send(proto, 'A1 LOGIN admin wrongpass')
    assert b"A1 NO" in b"".join(written)
    assert proto._state == "NOT_AUTHENTICATED"

def test_imap_select_before_auth(imap_mod):
    proto, transport, written = _make_protocol(imap_mod)
    _send(proto, 'A2 SELECT INBOX')
    assert b"A2 BAD" in b"".join(written)

def test_imap_fetch_after_select(imap_mod):
    proto, transport, written = _make_protocol(imap_mod)
    _send(proto, 'A1 LOGIN admin admin123')
    written.clear()
    _send(proto, 'A2 SELECT INBOX')
    written.clear()
    _send(proto, 'A3 FETCH 1 RFC822')
    combined = b"".join(written)
    assert b"A3 OK" in combined
    assert b"AKIAIOSFODNN7EXAMPLE" in combined

def test_imap_invalid_command(imap_mod):
    proto, transport, written = _make_protocol(imap_mod)
    _send(proto, 'A1 INVALID')
    assert b"A1 BAD" in b"".join(written)
