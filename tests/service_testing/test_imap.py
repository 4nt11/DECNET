"""
Tests for decnet/templates/imap/server.py

Exercises the full IMAP4rev1 state machine:
  NOT_AUTHENTICATED → AUTHENTICATED → SELECTED

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


def _load_imap():
    """Import imap server module, injecting a stub syslog_bridge."""
    env = {
        "NODE_NAME": "testhost",
        "IMAP_USERS": "admin:admin123,root:toor",
        "IMAP_BANNER": "* OK [testhost] Dovecot ready.",
    }
    for key in list(sys.modules):
        if key in ("imap_server", "syslog_bridge"):
            del sys.modules[key]

    sys.modules["syslog_bridge"] = _make_fake_syslog_bridge()

    spec = importlib.util.spec_from_file_location(
        "imap_server", "decnet/templates/imap/server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", env, clear=False):
        spec.loader.exec_module(mod)
    return mod


def _make_protocol(mod):
    """Return (protocol, transport, written). Banner already cleared."""
    proto = mod.IMAPProtocol()
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
    _send(proto, "A0 LOGIN admin admin123")
    written.clear()


def _select_inbox(proto, written):
    _send(proto, "B0 SELECT INBOX")
    written.clear()


@pytest.fixture
def imap_mod():
    return _load_imap()


# ── Tests: banner & unauthenticated ──────────────────────────────────────────

def test_imap_banner_on_connect(imap_mod):
    proto = imap_mod.IMAPProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    banner = b"".join(written)
    assert banner.startswith(b"* OK")


def test_imap_capability_contains_idle_and_literal_plus(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _send(proto, "C1 CAPABILITY")
    resp = _replies(written)
    assert b"IMAP4rev1" in resp
    assert b"IDLE" in resp
    assert b"LITERAL+" in resp
    assert b"AUTH=PLAIN" in resp


def test_imap_login_success(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _send(proto, "A1 LOGIN admin admin123")
    assert b"A1 OK" in _replies(written)
    assert proto._state == "AUTHENTICATED"


def test_imap_login_fail(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _send(proto, "A1 LOGIN admin wrongpass")
    resp = _replies(written)
    assert b"A1 NO" in resp
    assert b"AUTHENTICATIONFAILED" in resp
    assert proto._state == "NOT_AUTHENTICATED"


def test_imap_bad_creds_connection_stays_open(imap_mod):
    proto, transport, written = _make_protocol(imap_mod)
    _send(proto, "T1 LOGIN admin wrongpass")
    transport.close.assert_not_called()


def test_imap_retry_after_bad_credentials_succeeds(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _send(proto, "T1 LOGIN admin wrongpass")
    written.clear()
    _send(proto, "T2 LOGIN admin admin123")
    assert b"T2 OK" in _replies(written)
    assert proto._state == "AUTHENTICATED"


def test_imap_select_before_auth_returns_bad(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _send(proto, "A2 SELECT INBOX")
    assert b"A2 BAD" in _replies(written)


def test_imap_noop_unauthenticated_returns_ok(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _send(proto, "N1 NOOP")
    assert b"N1 OK" in _replies(written)


def test_imap_unknown_command_returns_bad(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _send(proto, "X1 INVALID_COMMAND")
    assert b"X1 BAD" in _replies(written)


# ── Tests: authenticated state ────────────────────────────────────────────────

def test_imap_list_returns_four_mailboxes(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _send(proto, 'L1 LIST "" "*"')
    resp = _replies(written)
    assert b"INBOX" in resp
    assert b"Sent" in resp
    assert b"Drafts" in resp
    assert b"Archive" in resp
    assert b"LIST completed" in resp


def test_imap_lsub_mirrors_list(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _send(proto, 'L2 LSUB "" "*"')
    resp = _replies(written)
    assert b"INBOX" in resp
    assert b"LSUB completed" in resp


def test_imap_status_inbox_messages(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _send(proto, "S0 STATUS INBOX (MESSAGES)")
    resp = _replies(written)
    assert b"STATUS INBOX" in resp
    assert b"MESSAGES 10" in resp


# ── Tests: SELECTED state ─────────────────────────────────────────────────────

def test_imap_select_inbox_exists_count(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _send(proto, "S1 SELECT INBOX")
    resp = _replies(written)
    assert b"* 10 EXISTS" in resp


def test_imap_select_inbox_uidnext(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _send(proto, "S1 SELECT INBOX")
    resp = _replies(written)
    assert b"UIDNEXT 11" in resp


def test_imap_select_inbox_read_write(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _send(proto, "S1 SELECT INBOX")
    resp = _replies(written)
    assert b"READ-WRITE" in resp


def test_imap_examine_inbox_read_only(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _send(proto, "S2 EXAMINE INBOX")
    resp = _replies(written)
    assert b"READ-ONLY" in resp


def test_imap_search_all_returns_all_seqs(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _select_inbox(proto, written)
    _send(proto, "Q1 SEARCH ALL")
    resp = _replies(written)
    assert b"* SEARCH 1 2 3 4 5 6 7 8 9 10" in resp


def test_imap_fetch_single_body_aws_key(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _select_inbox(proto, written)
    _send(proto, "F1 FETCH 1 BODY[]")
    resp = _replies(written)
    assert b"AKIAIOSFODNN7EXAMPLE" in resp
    assert b"F1 OK" in resp


def test_imap_fetch_after_select(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _send(proto, "A1 LOGIN admin admin123")
    written.clear()
    _send(proto, "A2 SELECT INBOX")
    written.clear()
    _send(proto, "A3 FETCH 1 RFC822")
    combined = _replies(written)
    assert b"A3 OK" in combined
    assert b"AKIAIOSFODNN7EXAMPLE" in combined


def test_imap_fetch_msg5_root_password(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _select_inbox(proto, written)
    _send(proto, "F2 FETCH 5 BODY[]")
    resp = _replies(written)
    assert b"r00tM3T00!" in resp


def test_imap_fetch_range_flags_envelope_count(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _select_inbox(proto, written)
    _send(proto, "F3 FETCH 1:3 (FLAGS ENVELOPE)")
    resp = _replies(written)
    assert b"* 1 FETCH" in resp
    assert b"* 2 FETCH" in resp
    assert b"* 3 FETCH" in resp
    assert b"FETCH completed" in resp


def test_imap_fetch_star_rfc822size_10_responses(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _select_inbox(proto, written)
    _send(proto, "F4 FETCH 1:* RFC822.SIZE")
    resp = _replies(written).decode(errors="replace")
    assert resp.count(" FETCH ") >= 10
    assert "F4 OK" in resp


def test_imap_uid_fetch_includes_uid_field(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _select_inbox(proto, written)
    _send(proto, "U1 UID FETCH 1:10 (FLAGS)")
    resp = _replies(written)
    assert b"UID 1" in resp
    assert b"FETCH completed" in resp


def test_imap_close_returns_to_authenticated(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _select_inbox(proto, written)
    _send(proto, "C1 CLOSE")
    resp = _replies(written)
    assert b"CLOSE completed" in resp
    assert proto._state == "AUTHENTICATED"


def test_imap_fetch_after_close_returns_bad(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _login(proto, written)
    _select_inbox(proto, written)
    _send(proto, "C1 CLOSE")
    written.clear()
    _send(proto, "C2 FETCH 1 FLAGS")
    assert b"C2 BAD" in _replies(written)


def test_imap_logout_sends_bye_and_closes(imap_mod):
    proto, transport, written = _make_protocol(imap_mod)
    _login(proto, written)
    _send(proto, "L1 LOGOUT")
    resp = _replies(written)
    assert b"* BYE" in resp
    assert b"LOGOUT completed" in resp
    transport.close.assert_called_once()


def test_imap_invalid_command(imap_mod):
    proto, _, written = _make_protocol(imap_mod)
    _send(proto, "A1 INVALID")
    assert b"A1 BAD" in _replies(written)
