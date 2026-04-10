"""
Tests for templates/pop3/server.py

Exercises POP3 state machine, auth, and negative tests.
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

def _load_pop3():
    env = {
        "NODE_NAME": "testhost",
        "IMAP_USERS": "admin:admin123,root:toor",
        "IMAP_BANNER": "+OK [testhost] Dovecot ready."
    }
    for key in list(sys.modules):
        if key in ("pop3_server", "decnet_logging"):
            del sys.modules[key]

    sys.modules["decnet_logging"] = _make_fake_decnet_logging()

    spec = importlib.util.spec_from_file_location("pop3_server", "templates/pop3/server.py")
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", env, clear=False):
        spec.loader.exec_module(mod)
    return mod

def _make_protocol(mod):
    proto = mod.POP3Protocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    written.clear()
    return proto, transport, written

def _send(proto, data: str) -> None:
    proto.data_received(data.encode() + b"\r\n")

@pytest.fixture
def pop3_mod():
    return _load_pop3()

def test_pop3_login_success(pop3_mod):
    proto, transport, written = _make_protocol(pop3_mod)
    _send(proto, 'USER admin')
    assert b"+OK" in b"".join(written)
    written.clear()
    _send(proto, 'PASS admin123')
    assert b"+OK Logged in" in b"".join(written)
    assert proto._state == "TRANSACTION"

def test_pop3_login_fail(pop3_mod):
    proto, transport, written = _make_protocol(pop3_mod)
    _send(proto, 'USER admin')
    written.clear()
    _send(proto, 'PASS wrongpass')
    assert b"-ERR" in b"".join(written)
    assert proto._state == "AUTHORIZATION"

def test_pop3_pass_before_user(pop3_mod):
    proto, transport, written = _make_protocol(pop3_mod)
    _send(proto, 'PASS admin123')
    assert b"-ERR" in b"".join(written)

def test_pop3_stat_before_auth(pop3_mod):
    proto, transport, written = _make_protocol(pop3_mod)
    _send(proto, 'STAT')
    assert b"-ERR" in b"".join(written)

def test_pop3_retr_after_auth(pop3_mod):
    proto, transport, written = _make_protocol(pop3_mod)
    _send(proto, 'USER admin')
    _send(proto, 'PASS admin123')
    written.clear()
    _send(proto, 'RETR 1')
    combined = b"".join(written)
    assert b"+OK" in combined
    assert b"AKIAIOSFODNN7EXAMPLE" in combined

def test_pop3_invalid_command(pop3_mod):
    proto, transport, written = _make_protocol(pop3_mod)
    _send(proto, 'INVALID')
    assert b"-ERR" in b"".join(written)
