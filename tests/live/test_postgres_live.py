import pytest

from tests.live.conftest import assert_rfc5424


@pytest.mark.live
class TestPostgresLive:
    def test_handshake_received(self, live_service):
        port, drain = live_service("postgres")
        import psycopg2
        try:
            psycopg2.connect(
                host="127.0.0.1",
                port=port,
                user="admin",
                password="password",
                dbname="production",
                connect_timeout=5,
            )
        except psycopg2.OperationalError:
            pass  # expected: honeypot rejects auth

    def test_startup_logged(self, live_service):
        port, drain = live_service("postgres")
        import psycopg2
        try:
            psycopg2.connect(
                host="127.0.0.1",
                port=port,
                user="postgres",
                password="secret",
                dbname="postgres",
                connect_timeout=5,
            )
        except psycopg2.OperationalError:
            pass
        lines = drain()
        assert_rfc5424(lines, service="postgres", event_type="startup")

    def test_username_in_log(self, live_service):
        port, drain = live_service("postgres")
        import psycopg2
        try:
            psycopg2.connect(
                host="127.0.0.1",
                port=port,
                user="dbattacker",
                password="cracked",
                dbname="secrets",
                connect_timeout=5,
            )
        except psycopg2.OperationalError:
            pass
        lines = drain()
        matched = assert_rfc5424(lines, service="postgres", event_type="startup")
        assert "dbattacker" in matched, (
            f"Expected username in log line. Got:\n{matched!r}"
        )

    def test_auth_hash_logged(self, live_service):
        port, drain = live_service("postgres")
        import psycopg2
        try:
            psycopg2.connect(
                host="127.0.0.1",
                port=port,
                user="root",
                password="toor",
                dbname="prod",
                connect_timeout=5,
            )
        except psycopg2.OperationalError:
            pass
        lines = drain()
        assert_rfc5424(lines, service="postgres", event_type="auth")
