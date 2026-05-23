# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
import redis

from tests.live.conftest import assert_rfc5424


@pytest.mark.live
class TestRedisLive:
    def test_ping_responds(self, live_service):
        port, drain = live_service("redis")
        r = redis.Redis(host="127.0.0.1", port=port, socket_timeout=5)
        assert r.ping() is True

    def test_connect_logged(self, live_service):
        port, drain = live_service("redis")
        r = redis.Redis(host="127.0.0.1", port=port, socket_timeout=5)
        r.ping()
        lines = drain()
        assert_rfc5424(lines, service="redis", event_type="connect")

    def test_auth_logged(self, live_service):
        port, drain = live_service("redis")
        r = redis.Redis(
            host="127.0.0.1", port=port, password="wrongpassword", socket_timeout=5
        )
        try:
            r.ping()
        except Exception:
            pass
        lines = drain()
        assert_rfc5424(lines, service="redis", event_type="auth")

    def test_command_logged(self, live_service):
        port, drain = live_service("redis")
        r = redis.Redis(host="127.0.0.1", port=port, socket_timeout=5)
        r.execute_command("KEYS", "*")
        lines = drain()
        assert_rfc5424(lines, service="redis", event_type="command")

    def test_keys_returns_bait_data(self, live_service):
        port, drain = live_service("redis")
        r = redis.Redis(host="127.0.0.1", port=port, socket_timeout=5)
        keys = r.keys("*")
        assert len(keys) > 0, "Expected bait keys in fake store"
