#!/usr/bin/env python3
"""
MQTT server (port 1883).
Parses MQTT CONNECT packets, extracts client_id, etc.
Responds with CONNACK.
Supports dynamic topics and retained publishes.
Logs PUBLISH commands sent by clients.
"""

import asyncio
import json
import os
import random
import struct
from syslog_bridge import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "mqtt-broker")
SERVICE_NAME   = "mqtt"
LOG_TARGET = os.environ.get("LOG_TARGET", "")
PORT = int(os.environ.get("PORT", "1883"))
MQTT_ACCEPT_ALL = os.environ.get("MQTT_ACCEPT_ALL", "1") == "1"
MQTT_PERSONA = os.environ.get("MQTT_PERSONA", "water_plant")
MQTT_CUSTOM_TOPICS = os.environ.get("MQTT_CUSTOM_TOPICS", "")

_CONNACK_ACCEPTED = b"\x20\x02\x00\x00"
_CONNACK_NOT_AUTH = b"\x20\x02\x00\x05"


def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


def _read_utf8(data: bytes, pos: int):
    """Read MQTT UTF-8 string (2-byte length prefix). Returns (string, next_pos)."""
    if pos + 2 > len(data):
        return "", pos
    length = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    return data[pos:pos + length].decode(errors="replace"), pos + length


def _parse_connect(payload: bytes):
    pos = 0
    proto_name, pos = _read_utf8(payload, pos)
    if pos >= len(payload):
        return {}, pos
    _proto_level = payload[pos]
    pos += 1
    if pos >= len(payload):
        return {}, pos
    flags = payload[pos]
    pos += 1
    pos += 2  # Keep alive
    client_id, pos = _read_utf8(payload, pos)
    result = {"client_id": client_id, "proto": proto_name}
    if flags & 0x04:
        _, pos = _read_utf8(payload, pos)
        _, pos = _read_utf8(payload, pos)
    if flags & 0x80:
        username, pos = _read_utf8(payload, pos)
        result["username"] = username
    if flags & 0x40:
        password, pos = _read_utf8(payload, pos)
        result["password"] = password
    return result


def _parse_subscribe(payload: bytes):
    """Returns (packet_id, [(topic, qos), ...])"""
    if len(payload) < 2:
        return 0, []
    pos = 0
    packet_id = struct.unpack(">H", payload[pos:pos+2])[0]
    pos += 2
    topics = []
    while pos < len(payload):
        topic, pos = _read_utf8(payload, pos)
        if pos >= len(payload):
            break
        qos = payload[pos] & 0x03
        pos += 1
        topics.append((topic, qos))
    return packet_id, topics


def _suback(packet_id: int, granted_qos: list[int]) -> bytes:
    payload = struct.pack(">H", packet_id) + bytes(granted_qos)
    return bytes([0x90, len(payload)]) + payload


def _publish(topic: str, value: str, retain: bool = True) -> bytes:
    topic_bytes = topic.encode()
    topic_len   = struct.pack(">H", len(topic_bytes))
    payload     = str(value).encode()
    fixed = 0x31 if retain else 0x30
    remaining = len(topic_len) + len(topic_bytes) + len(payload)

    # variable length encoding
    rem_bytes = []
    while remaining > 0:
        encoded = remaining % 128
        remaining = remaining // 128
        if remaining > 0:
            encoded = encoded | 128
        rem_bytes.append(encoded)
    if not rem_bytes:
        rem_bytes = [0]

    return bytes([fixed]) + bytes(rem_bytes) + topic_len + topic_bytes + payload


def _parse_publish(payload: bytes, qos: int):
    pos = 0
    topic, pos = _read_utf8(payload, pos)
    packet_id = 0
    if qos > 0:
        if pos + 2 <= len(payload):
            packet_id = struct.unpack(">H", payload[pos:pos+2])[0]
            pos += 2
    data = payload[pos:]
    return topic, packet_id, data


def _generate_topics() -> dict:
    topics: dict = {}
    if MQTT_CUSTOM_TOPICS:
        try:
            topics = json.loads(MQTT_CUSTOM_TOPICS)
            return topics
        except Exception as e:
            _log("config_error", severity=4, error=str(e))

    if MQTT_PERSONA == "water_plant":
        topics.update({
            "plant/water/tank1/level": f"{random.uniform(60.0, 80.0):.1f}",
            "plant/water/tank1/pressure": f"{random.uniform(2.5, 3.0):.2f}",
            "plant/water/pump1/status": "RUNNING",
            "plant/water/pump1/rpm": f"{int(random.uniform(1400, 1450))}",
            "plant/water/pump2/status": "STANDBY",
            "plant/water/chlorine/dosing": f"{random.uniform(1.1, 1.3):.1f}",
            "plant/water/chlorine/residual": f"{random.uniform(0.7, 0.9):.1f}",
            "plant/water/valve/inlet/state": "OPEN",
            "plant/water/valve/drain/state": "CLOSED",
            "plant/alarm/high_pressure": "0",
            "plant/alarm/low_chlorine": "0",
            "plant/alarm/pump_fault": "0",
            "plant/$SYS/broker/version": "Mosquitto 2.0.15",
            "plant/$SYS/broker/uptime": "2847392",
        })
    elif not topics:
        topics = {
            "device/status": "online",
            "device/uptime": "3600"
        }
    return topics


class MQTTProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
        self._buf = b""
        self._auth = False
        self._topics = _generate_topics()

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])

    def data_received(self, data):
        self._buf += data
        try:
            self._process()
        except Exception as e:
            _log("protocol_error", severity=4, error=str(e))
            if self._transport:
                self._transport.close()

    def _process(self):
        while len(self._buf) >= 2:
            pkt_byte = self._buf[0]
            pkt_type = (pkt_byte >> 4) & 0x0f
            flags = pkt_byte & 0x0f
            qos = (flags >> 1) & 0x03

            # Decode remaining length (variable-length encoding)
            pos = 1
            remaining = 0
            multiplier = 1
            while pos < len(self._buf):
                if pos > 4:  # MQTT spec: max 4 bytes for remaining length
                    self._transport.close()
                    self._buf = b""
                    return
                byte = self._buf[pos]
                remaining += (byte & 0x7f) * multiplier
                multiplier *= 128
                pos += 1
                if not (byte & 0x80):
                    break
            else:
                return  # incomplete length
            if len(self._buf) < pos + remaining:
                return  # incomplete payload
            payload = self._buf[pos:pos + remaining]
            self._buf = self._buf[pos + remaining:]

            if pkt_type == 1:  # CONNECT
                info = _parse_connect(payload)
                _log("auth", **info)
                if MQTT_ACCEPT_ALL:
                    self._auth = True
                    self._transport.write(_CONNACK_ACCEPTED)
                else:
                    self._transport.write(_CONNACK_NOT_AUTH)
                    self._transport.close()
            elif pkt_type == 8:  # SUBSCRIBE
                if not self._auth:
                    self._transport.close()
                    continue
                packet_id, subs = _parse_subscribe(payload)
                granted_qos = [1] * len(subs)  # grant QoS 1 for all
                self._transport.write(_suback(packet_id, granted_qos))

                # Immediately send retained publishes matching topics
                for sub_topic, _ in subs:
                    _log("subscribe", src=self._peer[0], topics=[sub_topic])
                    for t, v in self._topics.items():
                        # simple match: if topic ends with #, it matches prefix
                        if sub_topic.endswith("#"):
                            prefix = sub_topic[:-1]
                            if t.startswith(prefix):
                                self._transport.write(_publish(t, str(v)))
                        elif sub_topic == t:
                            self._transport.write(_publish(t, str(v)))

            elif pkt_type == 3:  # PUBLISH
                if not self._auth:
                    self._transport.close()
                    continue
                topic, packet_id, data = _parse_publish(payload, qos)
                # Attacker command received!
                _log("publish", src=self._peer[0], topic=topic, payload=data.decode(errors="replace"))

                if qos == 1:
                    puback = bytes([0x40, 0x02]) + struct.pack(">H", packet_id)
                    self._transport.write(puback)

            elif pkt_type == 12:  # PINGREQ
                self._transport.write(b"\xd0\x00")  # PINGRESP
            elif pkt_type == 14:  # DISCONNECT
                self._transport.close()
            else:
                _log("packet", src=self._peer[0], pkt_type=pkt_type)
                self._transport.close()

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"MQTT server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(MQTTProtocol, "0.0.0.0", PORT)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
