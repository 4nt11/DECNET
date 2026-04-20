"""
Tests for decnet/templates/mqtt/server.py

Exercises behavior with MQTT_ACCEPT_ALL=1 and customizable topics.
Uses asyncio transport/protocol directly.
"""

import importlib.util
import json
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


def _load_mqtt(accept_all: bool = True, custom_topics: str = "", persona: str = "water_plant"):
    env = {
        "MQTT_ACCEPT_ALL": "1" if accept_all else "0",
        "NODE_NAME": "testhost",
        "MQTT_PERSONA": persona,
        "MQTT_CUSTOM_TOPICS": custom_topics,
    }
    for key in list(sys.modules):
        if key in ("mqtt_server", "syslog_bridge"):
            del sys.modules[key]

    sys.modules["syslog_bridge"] = _make_fake_syslog_bridge()

    spec = importlib.util.spec_from_file_location("mqtt_server", "decnet/templates/mqtt/server.py")
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", env, clear=False):
        spec.loader.exec_module(mod)
    return mod


def _make_protocol(mod):
    proto = mod.MQTTProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    written.clear()
    return proto, transport, written


def _send(proto, data: bytes) -> None:
    proto.data_received(data)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mqtt_mod():
    return _load_mqtt()

@pytest.fixture
def mqtt_no_auth_mod():
    return _load_mqtt(accept_all=False)


# ── Packet Helpers ────────────────────────────────────────────────────────────

def _connect_packet() -> bytes:
    # 0x10, len 14, 00 04 MQTT 04 02 00 3c 00 02 id
    return b"\x10\x0e\x00\x04MQTT\x04\x02\x00\x3c\x00\x02id"

def _subscribe_packet(topic: str, pid: int = 1) -> bytes:
    topic_bytes = topic.encode()
    payload = pid.to_bytes(2, "big") + len(topic_bytes).to_bytes(2, "big") + topic_bytes + b"\x01" # qos 1
    return bytes([0x82, len(payload)]) + payload

def _publish_packet(topic: str, payload: str, qos: int = 1, pid: int = 1) -> bytes:
    topic_bytes = topic.encode()
    payload_bytes = payload.encode()
    flags = qos << 1
    byte0 = 0x30 | flags
    if qos > 0:
        packet_payload = len(topic_bytes).to_bytes(2, "big") + topic_bytes + pid.to_bytes(2, "big") + payload_bytes
    else:
        packet_payload = len(topic_bytes).to_bytes(2, "big") + topic_bytes + payload_bytes

    return bytes([byte0, len(packet_payload)]) + packet_payload

def _pingreq_packet() -> bytes:
    return b"\xc0\x00"

def _disconnect_packet() -> bytes:
    return b"\xe0\x00"


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_connect_accept(mqtt_mod):
    proto, transport, written = _make_protocol(mqtt_mod)
    _send(proto, _connect_packet())
    assert len(written) == 1
    assert written[0] == b"\x20\x02\x00\x00"
    assert proto._auth is True

def test_connect_reject(mqtt_no_auth_mod):
    proto, transport, written = _make_protocol(mqtt_no_auth_mod)
    _send(proto, _connect_packet())
    assert len(written) == 1
    assert written[0] == b"\x20\x02\x00\x05"
    assert transport.close.called

def test_pingreq(mqtt_mod):
    proto, _, written = _make_protocol(mqtt_mod)
    _send(proto, _pingreq_packet())
    assert written[0] == b"\xd0\x00"

def test_subscribe_wildcard_retained(mqtt_mod):
    proto, _, written = _make_protocol(mqtt_mod)
    _send(proto, _connect_packet())
    written.clear()

    _send(proto, _subscribe_packet("plant/#"))

    assert len(written) >= 2 # At least SUBACK + some publishes
    assert written[0].startswith(b"\x90") # SUBACK

    combined = b"".join(written[1:])
    # Should contain some water plant topics
    assert b"plant/water/tank1/level" in combined

def test_publish_qos1_returns_puback(mqtt_mod):
    proto, _, written = _make_protocol(mqtt_mod)
    _send(proto, _connect_packet())
    written.clear()

    _send(proto, _publish_packet("target/topic", "malicious_payload", qos=1, pid=42))
    assert len(written) == 1
    # PUBACK (0x40), len=2, pid=42
    assert written[0] == b"\x40\x02\x00\x2a"

def test_custom_topics():
    custom = {"custom/1": "val1", "custom/2": "val2"}
    mod = _load_mqtt(custom_topics=json.dumps(custom))
    proto, _, written = _make_protocol(mod)
    _send(proto, _connect_packet())
    written.clear()

    _send(proto, _subscribe_packet("custom/1"))
    assert len(written) > 1
    combined = b"".join(written[1:])
    assert b"custom/1" in combined
    assert b"val1" in combined

# ── Negative Tests ────────────────────────────────────────────────────────────

def test_subscribe_before_auth_closes(mqtt_mod):
    proto, transport, written = _make_protocol(mqtt_mod)
    _send(proto, _subscribe_packet("plant/#"))
    assert transport.close.called

def test_publish_before_auth_closes(mqtt_mod):
    proto, transport, written = _make_protocol(mqtt_mod)
    _send(proto, _publish_packet("test", "test", qos=0))
    assert transport.close.called

def test_malformed_connect_len(mqtt_mod):
    proto, transport, _ = _make_protocol(mqtt_mod)
    _send(proto, b"\x10\x05\x00\x04MQT")
    # buffer handles it
    _send(proto, b"\x10\x02\x00\x04")
    # No crash

def test_bad_packet_type_closer(mqtt_mod):
    proto, transport, _ = _make_protocol(mqtt_mod)
    _send(proto, b"\xf0\x00") # Reserved type 15
    assert transport.close.called

def test_invalid_json_config():
    mod = _load_mqtt(custom_topics="{invalid: json}")
    proto, _, _ = _make_protocol(mod)
    assert len(proto._topics) > 0 # fell back to persona

def test_disconnect_packet(mqtt_mod):
    proto, transport, _ = _make_protocol(mqtt_mod)
    _send(proto, _connect_packet())
    _send(proto, _disconnect_packet())
    assert transport.close.called
