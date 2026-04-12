import pytest
import pymysql

from tests.live.conftest import assert_rfc5424


@pytest.mark.live
class TestMySQLLive:
    def test_handshake_received(self, live_service):
        port, drain = live_service("mysql")
        # Honeypot sends MySQL greeting then denies auth — OperationalError expected
        try:
            pymysql.connect(
                host="127.0.0.1",
                port=port,
                user="root",
                password="password",
                connect_timeout=5,
            )
        except pymysql.err.OperationalError:
            pass  # expected: Access denied

    def test_auth_logged(self, live_service):
        port, drain = live_service("mysql")
        try:
            pymysql.connect(
                host="127.0.0.1",
                port=port,
                user="admin",
                password="hunter2",
                connect_timeout=5,
            )
        except pymysql.err.OperationalError:
            pass
        lines = drain()
        assert_rfc5424(lines, service="mysql", event_type="auth")

    def test_username_in_log(self, live_service):
        port, drain = live_service("mysql")
        try:
            pymysql.connect(
                host="127.0.0.1",
                port=port,
                user="dbhacker",
                password="letmein",
                connect_timeout=5,
            )
        except pymysql.err.OperationalError:
            pass
        lines = drain()
        matched = assert_rfc5424(lines, service="mysql", event_type="auth")
        assert "dbhacker" in matched, (
            f"Expected username in log line. Got:\n{matched!r}"
        )

    def test_connect_logged(self, live_service):
        port, drain = live_service("mysql")
        try:
            pymysql.connect(
                host="127.0.0.1", port=port, user="x", password="y", connect_timeout=5
            )
        except pymysql.err.OperationalError:
            pass
        lines = drain()
        assert_rfc5424(lines, service="mysql", event_type="connect")
