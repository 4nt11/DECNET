#!/usr/bin/env python3
"""
MySQLserver.
Sends a realistic MySQL 5.7 server handshake, reads the client login
packet, extracts username, then closes with Access Denied. Logs auth
attempts as JSON.
"""

import asyncio
import os
import struct
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME     = os.environ.get("NODE_NAME", "dbserver")
SERVICE_NAME   = "mysql"
LOG_TARGET    = os.environ.get("LOG_TARGET", "")
PORT          = int(os.environ.get("PORT", "3306"))
_MYSQL_VER    = os.environ.get("MYSQL_VERSION", "5.7.38-log")

# Minimal MySQL server greeting (protocol v10) — version string is configurable
_GREETING = (
    b"\x0a"                              # protocol version 10
    + _MYSQL_VER.encode() + b"\x00"     # server version + NUL
    + b"\x01\x00\x00\x00"               # connection id = 1
    + b"\x70\x76\x21\x6d\x61\x67\x69\x63"  # auth-plugin-data part 1
    + b"\x00"                            # filler
    + b"\xff\xf7"                        # capability flags low
    + b"\x21"                            # charset utf8
    + b"\x02\x00"                        # status flags
    + b"\xff\x81"                        # capability flags high
    + b"\x15"                            # auth plugin data length
    + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # reserved (10 bytes)
    + b"\x21\x4f\x7d\x25\x3e\x55\x4d\x7c\x67\x75\x5e\x31\x00"  # auth part 2
    + b"mysql_native_password\x00"       # auth plugin name
)


def _make_packet(payload: bytes, seq: int = 0) -> bytes:
    length = len(payload)
    return struct.pack("<I", length)[:3] + bytes([seq]) + payload




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


class MySQLProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
        self._buf = b""
        self._greeted = False

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])
        transport.write(_make_packet(_GREETING, seq=0))
        self._greeted = True

    def data_received(self, data):
        self._buf += data
        # MySQL packets: 3-byte length + 1-byte seq + payload
        while len(self._buf) >= 4:
            length = struct.unpack("<I", self._buf[:3] + b"\x00")[0]
            if length > 1024 * 1024:
                self._transport.close()
                self._buf = b""
                return
            if len(self._buf) < 4 + length:
                break
            payload = self._buf[4:4 + length]
            self._buf = self._buf[4 + length:]
            self._handle_packet(payload)

    def _handle_packet(self, payload: bytes):
        if not payload:
            return
        # Login packet: capability flags (4), max_packet (4), charset (1), reserved (23), username (NUL-terminated)
        if len(payload) > 32:
            try:
                # skip capability(4) + max_pkt(4) + charset(1) + reserved(23) = 32 bytes
                username_start = 32
                nul = payload.index(b"\x00", username_start)
                username = payload[username_start:nul].decode(errors="replace")
            except (ValueError, IndexError):
                username = "<parse_error>"
            _log("auth", src=self._peer[0], username=username)
        # Send Access Denied error
        err = b"\xff" + struct.pack("<H", 1045) + b"#28000Access denied for user\x00"
        self._transport.write(_make_packet(err, seq=2))
        self._transport.close()

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"MySQL server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(MySQLProtocol, "0.0.0.0", PORT)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
