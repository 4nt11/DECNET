import importlib.util
import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest


def _make_fake_syslog_bridge() -> ModuleType:
    mod = ModuleType("syslog_bridge")
    mod.syslog_line = MagicMock(return_value="")
    mod.write_syslog_file = MagicMock()
    mod.forward_syslog = MagicMock()
    mod.SEVERITY_WARNING = 4
    mod.SEVERITY_INFO = 6
    return mod


def _load_redis():
    env = {"NODE_NAME": "testredis"}
    for key in list(sys.modules):
        if key in ("redis_server", "syslog_bridge"):
            del sys.modules[key]

    sys.modules["syslog_bridge"] = _make_fake_syslog_bridge()

    spec = importlib.util.spec_from_file_location("redis_server", "decnet/templates/redis/server.py")
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", env, clear=False):
        spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def redis_mod():
    return _load_redis()


def _make_protocol(mod):
    proto = mod.RedisProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    written.clear()
    return proto, transport, written


def _send(proto, *lines: bytes) -> None:
    for line in lines:
        proto.data_received(line)


def test_auth_accepted(redis_mod):
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"AUTH password\r\n")
    assert b"".join(written) == b"+OK\r\n"


def test_keys_wildcard(redis_mod):
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n")
    response = b"".join(written)
    assert response.startswith(b"*10\r\n")
    assert b"config:aws_access_key" in response


def test_keys_prefix(redis_mod):
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"*2\r\n$4\r\nKEYS\r\n$6\r\nuser:*\r\n")
    response = b"".join(written)
    assert response.startswith(b"*2\r\n")
    assert b"user:admin" in response


def test_get_valid_key(redis_mod):
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"*2\r\n$3\r\nGET\r\n$13\r\ncache:api_key\r\n")
    response = b"".join(written)
    assert response == b"$38\r\nsk_live_9mK3xF2aP7qR1bN8cT4dW6vE0yU5hJ\r\n"


def test_get_invalid_key(redis_mod):
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"*2\r\n$3\r\nGET\r\n$7\r\nunknown\r\n")
    response = b"".join(written)
    assert response == b"$-1\r\n"


def test_scan(redis_mod):
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"*1\r\n$4\r\nSCAN\r\n")
    response = b"".join(written)
    assert response.startswith(b"*2\r\n$1\r\n0\r\n*10\r\n")


def test_type_and_ttl(redis_mod):
    proto, _, written = _make_protocol(redis_mod)
    _send(proto, b"TYPE somekey\r\n")
    assert b"".join(written) == b"+string\r\n"
    written.clear()

    _send(proto, b"TTL somekey\r\n")
    assert b"".join(written) == b":-1\r\n"
