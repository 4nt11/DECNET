import poplib

import pytest

from tests.live.conftest import assert_rfc5424


@pytest.mark.live
class TestPOP3Live:
    def test_banner_received(self, live_service):
        port, drain = live_service("pop3")
        pop = poplib.POP3("127.0.0.1", port)
        welcome = pop.getwelcome().decode()
        pop.quit()
        assert "+OK" in welcome

    def test_connect_logged(self, live_service):
        port, drain = live_service("pop3")
        pop = poplib.POP3("127.0.0.1", port)
        pop.quit()
        lines = drain()
        assert_rfc5424(lines, service="pop3", event_type="connect")

    def test_user_command_logged(self, live_service):
        port, drain = live_service("pop3")
        pop = poplib.POP3("127.0.0.1", port)
        pop.user("admin")
        pop.quit()
        lines = drain()
        assert_rfc5424(lines, service="pop3", event_type="command")

    def test_auth_success_logged(self, live_service):
        port, drain = live_service("pop3")
        pop = poplib.POP3("127.0.0.1", port)
        pop.user("admin")
        pop.pass_("admin123")  # valid cred from IMAP_USERS default
        lines = drain()
        pop.quit()
        lines += drain()
        matched = assert_rfc5424(lines, service="pop3", event_type="auth")
        assert "success" in matched, f"Expected auth success in log. Got:\n{matched!r}"

    def test_auth_fail_logged(self, live_service):
        port, drain = live_service("pop3")
        pop = poplib.POP3("127.0.0.1", port)
        pop.user("root")
        try:
            pop.pass_("wrongpassword")
        except poplib.error_proto:
            pass  # expected: -ERR Authentication failed
        lines = drain()
        try:
            pop.quit()
        except Exception:
            pass
        lines += drain()
        matched = assert_rfc5424(lines, service="pop3", event_type="auth")
        assert "failed" in matched, f"Expected auth failure in log. Got:\n{matched!r}"
