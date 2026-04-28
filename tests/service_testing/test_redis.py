import importlib.util
import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from tests.service_testing.conftest import (
    load_real_instance_seed,
    make_fake_syslog_bridge,
)


def _load_redis(node_name: str = "testredis"):
    env = {"NODE_NAME": node_name}
    for key in ("redis_server", "syslog_bridge", "instance_seed"):
        sys.modules.pop(key, None)

    sys.modules["syslog_bridge"] = make_fake_syslog_bridge()

    # Pin NODE_NAME before loading instance_seed — the seed is derived at
    # import time.
    with patch.dict("os.environ", env, clear=False):
        sys.modules["instance_seed"] = load_real_instance_seed()
        spec = importlib.util.spec_from_file_location(
            "redis_server", "decnet/templates/redis/server.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def redis_mod():
    return _load_redis()


def _make_protocol(mod):
    proto = mod.RedisProtocol()
    transport = MagicMock()
    transport.is_closing.return_value = False
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    written.clear()
    return proto, transport, written


def _send(proto, *lines: bytes) -> None:
    for line in lines:
        proto.data_received(line)


def test_auth_with_no_password_configured(redis_mod, monkeypatch):
    """Default config has no REDIS_PASSWORD — real redis rejects AUTH with
    the 'no password is set' ERR message. Accepting any AUTH blindly (the
    old behavior) is a honeypot tell."""
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"AUTH password\r\n")
    resp = b"".join(written)
    assert resp.startswith(b"-ERR")
    assert b"no password is set" in resp


def test_keys_pattern_yields_subset(redis_mod):
    """Fake store contents are now per-instance. We can't assert exact keys,
    but KEYS with a narrow prefix should still return a proper RESP array
    whose length matches the filtered subset."""
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"*2\r\n$4\r\nKEYS\r\n$8\r\nsession:\r\n")
    response = b"".join(written)
    assert response.startswith(b"*0\r\n")  # no key equals literal "session:"


def test_keys_star_returns_all(redis_mod):
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n")
    response = b"".join(written)
    # First bulk line is the array length; at least 1 key must exist.
    assert response.startswith(b"*")
    count = int(response.split(b"\r\n", 1)[0][1:])
    assert count >= 1


def test_config_get_returns_real_kv_pairs(redis_mod):
    """Old server returned *0 for CONFIG — a strong honeypot signature.
    New behavior returns real config key/value pairs."""
    proto, _, written = _make_protocol(redis_mod)
    # Use a wildcard to make the length prefix unambiguous and match both
    # "maxmemory" and "maxmemory-policy".
    _send(proto, b"*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$10\r\nmaxmemory*\r\n")
    response = b"".join(written)
    assert response.startswith(b"*4\r\n")  # 2 keys × (key+value) = 4 elements
    assert b"maxmemory" in response
    assert b"maxmemory-policy" in response


def test_info_has_dynamic_uptime(redis_mod):
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"*1\r\n$4\r\nINFO\r\n")
    response = b"".join(written)
    assert b"uptime_in_seconds:" in response
    # Old server hard-coded 864000 — ensure we're not regressing.
    assert b"uptime_in_seconds:864000\r\n" not in response


def test_per_instance_version_differs_across_decky_names():
    """Two deckies with different NODE_NAMEs should, with high probability,
    pick different redis versions from the weighted pool."""
    picks: set[str] = set()
    for name in ("decky-a", "decky-b", "decky-c", "decky-d", "decky-e", "decky-f"):
        mod = _load_redis(node_name=name)
        picks.add(mod._REDIS_VER)
    assert len(picks) >= 2


def test_type_and_ttl(redis_mod):
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"TYPE somekey\r\n")
    assert b"+string\r\n" in b"".join(written)
    written.clear()
    _send(proto, b"TTL somekey\r\n")
    assert b":-1\r\n" in b"".join(written)
