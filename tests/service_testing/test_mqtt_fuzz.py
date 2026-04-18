"""
Tests for templates/mqtt/server.py — protocol boundary and fuzz cases.

Focuses on the variable-length remaining-length field (MQTT spec: max 4 bytes).
A 5th continuation byte used to cause the server to get stuck waiting for a
payload it could never receive (remaining = hundreds of MB).
"""

import importlib.util
import struct
import sys
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from .conftest import _FUZZ_SETTINGS, make_fake_syslog_bridge, run_with_timeout


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_mqtt():
    for key in list(sys.modules):
        if key in ("mqtt_server", "syslog_bridge"):
            del sys.modules[key]
    sys.modules["syslog_bridge"] = make_fake_syslog_bridge()
    spec = importlib.util.spec_from_file_location("mqtt_server", "templates/mqtt/server.py")
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", {"MQTT_ACCEPT_ALL": "1", "MQTT_PERSONA": "water_plant"}, clear=False):
        spec.loader.exec_module(mod)
    return mod


def _make_protocol(mod):
    proto = mod.MQTTProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    return proto, transport, written


def _connect_packet(client_id: str = "test-client") -> bytes:
    """Build a minimal MQTT CONNECT packet."""
    proto_name = b"\x00\x04MQTT"
    proto_level = b"\x04"  # 3.1.1
    flags = b"\x02"        # clean session
    keepalive = b"\x00\x3c"
    cid = client_id.encode()
    cid_field = struct.pack(">H", len(cid)) + cid
    payload = proto_name + proto_level + flags + keepalive + cid_field
    remaining = len(payload)
    # single-byte remaining length (works for short payloads)
    return bytes([0x10, remaining]) + payload


def _encode_remaining(value: int) -> bytes:
    """Encode a value using MQTT variable-length encoding."""
    result = []
    while True:
        encoded = value % 128
        value //= 128
        if value > 0:
            encoded |= 128
        result.append(encoded)
        if value == 0:
            break
    return bytes(result)


@pytest.fixture
def mqtt_mod():
    return _load_mqtt()


# ── Happy path ────────────────────────────────────────────────────────────────

def test_connect_returns_connack_accepted(mqtt_mod):
    proto, _, written = _make_protocol(mqtt_mod)
    proto.data_received(_connect_packet())
    resp = b"".join(written)
    assert resp[:2] == b"\x20\x02"  # CONNACK
    assert resp[3:4] == b"\x00"    # return code 0 = accepted


def test_connect_sets_auth_flag(mqtt_mod):
    proto, _, _ = _make_protocol(mqtt_mod)
    proto.data_received(_connect_packet())
    assert proto._auth is True


def test_pingreq_returns_pingresp(mqtt_mod):
    proto, _, written = _make_protocol(mqtt_mod)
    proto.data_received(_connect_packet())
    written.clear()
    proto.data_received(b"\xc0\x00")  # PINGREQ
    assert b"\xd0\x00" in b"".join(written)


def test_disconnect_closes_transport(mqtt_mod):
    proto, transport, _ = _make_protocol(mqtt_mod)
    proto.data_received(_connect_packet())
    transport.reset_mock()
    proto.data_received(b"\xe0\x00")  # DISCONNECT
    transport.close.assert_called()


def test_publish_without_auth_closes(mqtt_mod):
    proto, transport, _ = _make_protocol(mqtt_mod)
    # PUBLISH without prior CONNECT
    topic = b"\x00\x04test"
    payload = b"hello"
    remaining = len(topic) + len(payload)
    proto.data_received(bytes([0x30, remaining]) + topic + payload)
    transport.close.assert_called()


def test_partial_packet_waits_for_more(mqtt_mod):
    proto, transport, _ = _make_protocol(mqtt_mod)
    proto.data_received(b"\x10")  # just the first byte
    transport.close.assert_not_called()


def test_connection_lost_does_not_raise(mqtt_mod):
    proto, _, _ = _make_protocol(mqtt_mod)
    proto.connection_lost(None)


# ── Regression: overlong remaining-length field ───────────────────────────────

def test_5_continuation_bytes_closes(mqtt_mod):
    proto, transport, _ = _make_protocol(mqtt_mod)
    # 5 bytes with continuation bit set, then a final byte
    # MQTT spec allows max 4 bytes — this must be rejected
    data = bytes([0x30, 0x80, 0x80, 0x80, 0x80, 0x01])
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


def test_6_continuation_bytes_closes(mqtt_mod):
    proto, transport, _ = _make_protocol(mqtt_mod)
    data = bytes([0x30]) + bytes([0x80] * 6) + b"\x01"
    run_with_timeout(proto.data_received, data)
    transport.close.assert_called()


def test_4_continuation_bytes_is_accepted(mqtt_mod):
    proto, transport, _ = _make_protocol(mqtt_mod)
    # 4 bytes total for remaining length = max allowed.
    # remaining = 0x0FFFFFFF = 268435455 bytes — huge but spec-valid encoding.
    # With no data following, it simply returns (incomplete payload) — not closed.
    data = bytes([0x30, 0xff, 0xff, 0xff, 0x7f])
    run_with_timeout(proto.data_received, data)
    transport.close.assert_not_called()


def test_zero_remaining_publish_does_not_close(mqtt_mod):
    proto, transport, _ = _make_protocol(mqtt_mod)
    proto.data_received(_connect_packet())
    transport.reset_mock()
    # PUBLISH with remaining=0 is unusual but not a protocol violation
    proto.data_received(b"\x30\x00")
    transport.close.assert_not_called()


# ── Fuzz ──────────────────────────────────────────────────────────────────────

@pytest.mark.fuzz
@given(data=st.binary(min_size=0, max_size=512))
@settings(**_FUZZ_SETTINGS)
def test_fuzz_unauthenticated(data):
    mod = _load_mqtt()
    proto, _, _ = _make_protocol(mod)
    run_with_timeout(proto.data_received, data)


@pytest.mark.fuzz
@given(data=st.binary(min_size=0, max_size=512))
@settings(**_FUZZ_SETTINGS)
def test_fuzz_after_connect(data):
    mod = _load_mqtt()
    proto, _, _ = _make_protocol(mod)
    proto.data_received(_connect_packet())
    run_with_timeout(proto.data_received, data)
