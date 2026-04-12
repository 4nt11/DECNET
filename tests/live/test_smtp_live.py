import smtplib

import pytest

from tests.live.conftest import assert_rfc5424


@pytest.mark.live
class TestSMTPLive:
    def test_banner_received(self, live_service):
        port, drain = live_service("smtp")
        with smtplib.SMTP("127.0.0.1", port, timeout=5) as s:
            code, msg = s.ehlo("test.example.com")
        assert code == 250

    def test_ehlo_logged(self, live_service):
        port, drain = live_service("smtp")
        with smtplib.SMTP("127.0.0.1", port, timeout=5) as s:
            s.ehlo("attacker.example.com")
        lines = drain()
        assert_rfc5424(lines, service="smtp", event_type="ehlo")

    def test_auth_attempt_logged(self, live_service):
        port, drain = live_service("smtp")
        with smtplib.SMTP("127.0.0.1", port, timeout=5) as s:
            s.ehlo("attacker.example.com")
            try:
                s.login("admin", "password123")
            except smtplib.SMTPAuthenticationError:
                pass  # expected — honeypot rejects auth
        lines = drain()
        assert_rfc5424(lines, service="smtp", event_type="auth_attempt")

    def test_connect_disconnect_logged(self, live_service):
        port, drain = live_service("smtp")
        with smtplib.SMTP("127.0.0.1", port, timeout=5) as s:
            s.ehlo("scanner.example.com")
        lines = drain()
        assert_rfc5424(lines, service="smtp", event_type="connect")
