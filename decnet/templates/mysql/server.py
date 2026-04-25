#!/usr/bin/env python3
"""
MySQLserver.
Sends a realistic MySQL 5.7 server handshake, reads the client login
packet, extracts username, then closes with Access Denied. Logs auth
attempts as JSON.
"""

import asyncio
import base64
import itertools
import os
import struct

import instance_seed as _seed
from syslog_bridge import syslog_line, write_syslog_file, forward_syslog

NODE_NAME     = os.environ.get("NODE_NAME", "dbserver")
SERVICE_NAME   = "mysql"
LOG_TARGET    = os.environ.get("LOG_TARGET", "")
PORT          = int(os.environ.get("PORT", "3306"))

# Per-instance version. Real fleets never run one identical point release
# across every host — weighted mix of still-in-the-wild 5.7/8.0 builds.
_MYSQL_VER = os.environ.get("MYSQL_VERSION") or _seed.pick_weighted([
    ("5.7.38-log", 1),
    ("5.7.43-log", 2),
    ("5.7.44-log", 2),
    ("8.0.32", 2),
    ("8.0.35", 3),
    ("8.0.36", 3),
    ("8.0.39", 2),
    ("8.0.40", 1),
])

# Monotonic per-process counter for connection IDs. Seeded with a
# per-instance base so two deckies never hand out id=1 to the same scanner.
_CONN_ID_SEQ = itertools.count(_seed.rng.randint(17, 65_000))


def _build_greeting(conn_id: int, salt: bytes) -> bytes:
    """MySQL protocol v10 Initial Handshake Packet. salt is 20 bytes
    (8 + 12 split across two sections) and must be freshly random per
    connection — it's the challenge the client hashes its password against."""
    assert len(salt) == 20
    return (
        b"\x0a"
        + _MYSQL_VER.encode() + b"\x00"
        + struct.pack("<I", conn_id)
        + salt[:8]
        + b"\x00"
        + b"\xff\xf7"
        + b"\x21"
        + b"\x02\x00"
        + b"\xff\x81"
        + b"\x15"
        + b"\x00" * 10
        + salt[8:] + b"\x00"
        + b"mysql_native_password\x00"
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
        self._conn_id = next(_CONN_ID_SEQ) & 0xFFFFFFFF
        # 20-byte scramble; fresh per connection so two handshakes to the
        # same decky never present identical auth challenges.
        self._salt = _seed.fresh_bytes(20)

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1],
             connection_id=self._conn_id)
        transport.write(_make_packet(_build_greeting(self._conn_id, self._salt), seq=0))
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
        # Login packet: capability flags (4), max_packet (4), charset (1),
        # reserved (23), username (NUL-terminated), auth-response.
        # mysql_native_password puts a 1-byte length followed by exactly
        # 20 bytes: SHA1(password) XOR SHA1(salt + SHA1(SHA1(password))) —
        # plaintext is unrecoverable but the 20 bytes ARE a credential the
        # attacker knew, so they land as secret_kind="mysql_native_password".
        username = "<unknown>"
        auth_response = b""
        if len(payload) > 32:
            try:
                username_start = 32
                nul = payload.index(b"\x00", username_start)
                username = payload[username_start:nul].decode(errors="replace")
                # auth-response length byte + bytes
                if len(payload) > nul + 1:
                    resp_len = payload[nul + 1]
                    if resp_len and len(payload) >= nul + 2 + resp_len:
                        auth_response = payload[nul + 2:nul + 2 + resp_len]
            except (ValueError, IndexError):
                username = "<parse_error>"

            extra: dict = {}
            if auth_response:
                _b64 = base64.b64encode(auth_response).decode("ascii")
                extra = {
                    "principal": username,
                    "secret_kind": "mysql_native_password",
                    "secret_printable": auth_response.hex(),
                    "secret_b64": _b64,
                }
            _log("auth", src=self._peer[0], username=username,
                 connection_id=self._conn_id, **extra)
        # Real mysqld includes client IP in the error text.
        src_ip = self._peer[0] if self._peer else "?"
        msg = f"Access denied for user '{username}'@'{src_ip}' (using password: YES)"
        err = b"\xff" + struct.pack("<H", 1045) + b"#28000" + msg.encode()
        _seed.jitter_sync(15, 90)
        if self._transport and not self._transport.is_closing():
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
