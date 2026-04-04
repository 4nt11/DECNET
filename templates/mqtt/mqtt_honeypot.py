#!/usr/bin/env python3
"""
MQTT honeypot (port 1883).
Parses MQTT CONNECT packets, extracts client_id, username, and password,
then returns CONNACK with return code 5 (not authorized). Logs all
interactions as JSON.
"""

import asyncio
import json
import os
import socket
import struct
from datetime import datetime, timezone

HONEYPOT_NAME = os.environ.get("HONEYPOT_NAME", "mqtt-broker")
LOG_TARGET = os.environ.get("LOG_TARGET", "")

# CONNACK: packet type 0x20, remaining length 2, session_present=0, return_code=5
_CONNACK_NOT_AUTH = b"\x20\x02\x00\x05"


def _forward(event: dict) -> None:
    if not LOG_TARGET:
        return
    try:
        host, port = LOG_TARGET.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=3) as s:
            s.sendall((json.dumps(event) + "\n").encode())
    except Exception:
        pass


def _log(event_type: str, **kwargs) -> None:
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "service": "mqtt",
        "host": HONEYPOT_NAME,
        "event": event_type,
        **kwargs,
    }
    print(json.dumps(event), flush=True)
    _forward(event)


def _read_utf8(data: bytes, pos: int):
    """Read MQTT UTF-8 string (2-byte length prefix). Returns (string, next_pos)."""
    if pos + 2 > len(data):
        return "", pos
    length = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    return data[pos:pos + length].decode(errors="replace"), pos + length


def _parse_connect(payload: bytes):
    """Extract client_id, username, password from MQTT CONNECT payload."""
    pos = 0
    # Protocol name
    proto_name, pos = _read_utf8(payload, pos)
    # Protocol level (1 byte)
    if pos >= len(payload):
        return {}, pos
    _proto_level = payload[pos]; pos += 1
    # Connect flags (1 byte)
    if pos >= len(payload):
        return {}, pos
    flags = payload[pos]; pos += 1
    # Keep alive (2 bytes)
    pos += 2
    # Client ID
    client_id, pos = _read_utf8(payload, pos)
    result = {"client_id": client_id, "proto": proto_name}
    # Will flag
    if flags & 0x04:
        _, pos = _read_utf8(payload, pos)  # will topic
        _, pos = _read_utf8(payload, pos)  # will message
    # Username flag
    if flags & 0x80:
        username, pos = _read_utf8(payload, pos)
        result["username"] = username
    # Password flag
    if flags & 0x40:
        password, pos = _read_utf8(payload, pos)
        result["password"] = password
    return result


class MQTTProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
        self._buf = b""

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])

    def data_received(self, data):
        self._buf += data
        self._process()

    def _process(self):
        while len(self._buf) >= 2:
            pkt_type = (self._buf[0] >> 4) & 0x0f
            # Decode remaining length (variable-length encoding)
            pos = 1
            remaining = 0
            multiplier = 1
            while pos < len(self._buf):
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
                _log("auth", src=self._peer[0], **info)
                self._transport.write(_CONNACK_NOT_AUTH)
                self._transport.close()
            elif pkt_type == 12:  # PINGREQ
                self._transport.write(b"\xd0\x00")  # PINGRESP
            else:
                _log("packet", src=self._peer[0], pkt_type=pkt_type)
                self._transport.close()

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"MQTT honeypot starting as {HONEYPOT_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(MQTTProtocol, "0.0.0.0", 1883)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
