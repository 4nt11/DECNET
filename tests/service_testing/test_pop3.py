"""
Tests for templates/pop3/server.py

Exercises the full POP3 state machine:
  AUTHORIZATION → TRANSACTION

Uses asyncio Protocol directly — no network socket needed.
"""

import importlib.util
import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_fake_syslog_bridge() -> ModuleType:
    mod = ModuleType("syslog_bridge")
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
        "IMAP_BANNER": "+OK [testhost] Dovecot ready.",
    }
    for key in list(sys.modules):
        if key in ("pop3_server", "syslog_bridge"):
            del sys.modules[key]

    sys.modules["syslog_bridge"] = _make_fake_syslog_bridge()

    spec = importlib.util.spec_from_file_location(
        "pop3_server", "templates/pop3/server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", env, clear=False):
        spec.loader.exec_module(mod)
    return mod


def _make_protocol(mod):
    """Return (protocol, transport, written). Banner already cleared."""
    proto = mod.POP3Protocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    written.clear()
    return proto, transport, written


def _send(proto, data: str) -> None:
    proto.data_received(data.encode() + b"\r\n")


def _replies(written: list[bytes]) -> bytes:
    return b"".join(written)


def _login(proto, written):
    _send(proto, "USER admin")
    _send(proto, "PASS admin123")
    written.clear()


@pytest.fixture
def pop3_mod():
    return _load_pop3()


# ── Tests: banner & unauthenticated ──────────────────────────────────────────

def test_pop3_banner_starts_with_ok(pop3_mod):
    proto = pop3_mod.POP3Protocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    banner = b"".join(written)
    assert banner.startswith(b"+OK")


def test_pop3_capa_contains_top_uidl_user(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _send(proto, "CAPA")
    resp = _replies(written)
    assert b"TOP" in resp
    assert b"UIDL" in resp
    assert b"USER" in resp


def test_pop3_login_success(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _send(proto, "USER admin")
    assert b"+OK" in _replies(written)
    written.clear()
    _send(proto, "PASS admin123")
    assert b"+OK Logged in" in _replies(written)
    assert proto._state == "TRANSACTION"


def test_pop3_login_fail(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _send(proto, "USER admin")
    written.clear()
    _send(proto, "PASS wrongpass")
    assert b"-ERR" in _replies(written)
    assert proto._state == "AUTHORIZATION"


def test_pop3_bad_pass_connection_stays_open(pop3_mod):
    proto, transport, written = _make_protocol(pop3_mod)
    _send(proto, "USER admin")
    _send(proto, "PASS wrongpass")
    transport.close.assert_not_called()


def test_pop3_retry_after_bad_pass_succeeds(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _send(proto, "USER admin")
    _send(proto, "PASS wrongpass")
    written.clear()
    _send(proto, "USER admin")
    _send(proto, "PASS admin123")
    assert b"+OK Logged in" in _replies(written)


def test_pop3_pass_before_user(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _send(proto, "PASS admin123")
    assert b"-ERR" in _replies(written)


def test_pop3_stat_before_auth(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _send(proto, "STAT")
    assert b"-ERR" in _replies(written)


def test_pop3_retr_before_auth(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _send(proto, "RETR 1")
    assert b"-ERR" in _replies(written)


def test_pop3_invalid_command(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _send(proto, "INVALID")
    assert b"-ERR" in _replies(written)


# ── Tests: TRANSACTION state ──────────────────────────────────────────────────

def test_pop3_stat_10_messages(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _login(proto, written)
    _send(proto, "STAT")
    resp = _replies(written).decode()
    assert resp.startswith("+OK 10 ")


def test_pop3_list_returns_10_entries(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _login(proto, written)
    _send(proto, "LIST")
    resp = _replies(written).decode()
    assert resp.startswith("+OK 10")
    # Count individual message lines: "N size\r\n"
    entries = [entry for entry in resp.split("\r\n") if entry and entry[0].isdigit()]
    assert len(entries) == 10


def test_pop3_retr_after_auth_msg1(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _send(proto, "USER admin")
    _send(proto, "PASS admin123")
    written.clear()
    _send(proto, "RETR 1")
    combined = _replies(written)
    assert b"+OK" in combined
    assert b"AKIAIOSFODNN7EXAMPLE" in combined


def test_pop3_retr_msg5_root_password(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _login(proto, written)
    _send(proto, "RETR 5")
    resp = _replies(written)
    assert b"+OK" in resp
    assert b"r00tM3T00!" in resp


def test_pop3_top_returns_headers_plus_lines(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _login(proto, written)
    _send(proto, "TOP 1 3")
    resp = _replies(written).decode(errors="replace")
    assert resp.startswith("+OK")
    # Headers must be present
    assert "From:" in resp
    assert "Subject:" in resp
    # Should NOT contain body content beyond 3 lines — but 3 lines of the
    # AWS email body are enough to include the access key
    assert ".\r\n" in resp


def test_pop3_top_3_body_lines_count(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _login(proto, written)
    # Message 1 body after blank line:
    # "Team,\r\n", "\r\n", "New AWS credentials...\r\n", ...
    _send(proto, "TOP 1 3")
    resp = _replies(written).decode(errors="replace")
    # Strip headers up to blank line
    parts = resp.split("\r\n\r\n", 1)
    assert len(parts) == 2
    body_section = parts[1].rstrip("\r\n.")
    body_lines = [part for part in body_section.split("\r\n") if part != "."]
    assert len(body_lines) <= 3


def test_pop3_uidl_returns_10_entries(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _login(proto, written)
    _send(proto, "UIDL")
    resp = _replies(written).decode()
    assert resp.startswith("+OK")
    entries = [entry for entry in resp.split("\r\n") if entry and entry[0].isdigit()]
    assert len(entries) == 10


def test_pop3_uidl_format_msg_n(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _login(proto, written)
    _send(proto, "UIDL")
    resp = _replies(written).decode()
    assert "1 msg-1" in resp
    assert "5 msg-5" in resp


def test_pop3_dele_removes_message(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _login(proto, written)
    _send(proto, "DELE 3")
    resp = _replies(written)
    assert b"+OK" in resp
    assert 2 in proto._deleted  # 0-based


def test_pop3_rset_clears_deletions(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _login(proto, written)
    _send(proto, "DELE 1")
    _send(proto, "DELE 2")
    written.clear()
    _send(proto, "RSET")
    resp = _replies(written)
    assert b"+OK" in resp
    assert len(proto._deleted) == 0


def test_pop3_dele_then_stat_decrements_count(pop3_mod):
    proto, _, written = _make_protocol(pop3_mod)
    _login(proto, written)
    _send(proto, "DELE 1")
    written.clear()
    _send(proto, "STAT")
    resp = _replies(written).decode()
    assert resp.startswith("+OK 9 ")


def test_pop3_quit_closes_connection(pop3_mod):
    proto, transport, written = _make_protocol(pop3_mod)
    _login(proto, written)
    _send(proto, "QUIT")
    transport.close.assert_called_once()
