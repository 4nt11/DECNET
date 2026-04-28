import imaplib

import pytest

from tests.live.conftest import assert_rfc5424


@pytest.mark.live
class TestIMAPLive:
    def test_banner_received(self, live_service):
        port, drain = live_service("imap")
        imap = imaplib.IMAP4("127.0.0.1", port)
        welcome = imap.welcome.decode()
        imap.logout()
        assert "OK" in welcome

    def test_connect_logged(self, live_service):
        port, drain = live_service("imap")
        imap = imaplib.IMAP4("127.0.0.1", port)
        imap.logout()
        lines = drain()
        assert_rfc5424(lines, service="imap", event_type="connect")

    def test_login_logged(self, live_service):
        port, drain = live_service("imap")
        imap = imaplib.IMAP4("127.0.0.1", port)
        try:
            imap.login("admin", "wrongpass")
        except imaplib.IMAP4.error:
            pass
        lines = drain()
        try:
            imap.logout()
        except Exception:
            pass
        lines += drain()
        assert_rfc5424(lines, service="imap", event_type="auth")

    def test_auth_success_logged(self, live_service):
        port, drain = live_service("imap")
        imap = imaplib.IMAP4("127.0.0.1", port)
        imap.login("admin", "admin123")  # valid cred from IMAP_USERS default
        lines = drain()
        imap.logout()
        lines += drain()
        matched = assert_rfc5424(lines, service="imap", event_type="auth")
        assert "success" in matched, f"Expected auth success in log. Got:\n{matched!r}"

    def test_auth_fail_logged(self, live_service):
        port, drain = live_service("imap")
        imap = imaplib.IMAP4("127.0.0.1", port)
        try:
            imap.login("hacker", "crackedpassword")
        except imaplib.IMAP4.error:
            pass  # expected
        lines = drain()
        try:
            imap.logout()
        except Exception:
            pass
        lines += drain()
        matched = assert_rfc5424(lines, service="imap", event_type="auth")
        assert "failure" in matched, f"Expected auth failure in log. Got:\n{matched!r}"

    def test_select_inbox_after_login(self, live_service):
        port, drain = live_service("imap")
        imap = imaplib.IMAP4("127.0.0.1", port)
        imap.login("admin", "admin123")
        status, data = imap.select("INBOX")
        imap.logout()
        assert status == "OK", f"SELECT INBOX failed: {data}"

    def test_capability_command(self, live_service):
        port, drain = live_service("imap")
        imap = imaplib.IMAP4("127.0.0.1", port)
        status, caps = imap.capability()
        imap.logout()
        assert status == "OK"
        cap_str = b" ".join(caps).decode()
        assert "IMAP4rev1" in cap_str
