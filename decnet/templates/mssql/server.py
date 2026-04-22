#!/usr/bin/env python3
"""
MSSQL (TDS)server.
Reads TDS pre-login and login7 packets, extracts username, responds with
a login failed error. Logs auth attempts as JSON.
"""

import asyncio
import os
import struct

import instance_seed as _seed
from syslog_bridge import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "dbserver")
SERVICE_NAME   = "mssql"
LOG_TARGET = os.environ.get("LOG_TARGET", "")

# Real SQL Server release families. Pairing (major, minor, build) makes a
# subsequent OSQL/sqlcmd version probe line up with what MS published.
# Builds are taken from publicly documented latest-CU numbers.
_MSSQL_RELEASES = [
    # (name,            major, minor, build, subbuild)
    ("SQL Server 2016", 13, 0, 6419, 0),
    ("SQL Server 2017", 14, 0, 2000, 0),
    ("SQL Server 2017", 14, 0, 3460, 0),
    ("SQL Server 2019", 15, 0, 2000, 0),
    ("SQL Server 2019", 15, 0, 4335, 1),
    ("SQL Server 2022", 16, 0, 1000, 0),
    ("SQL Server 2022", 16, 0, 4115, 2),
]
_MSSQL_NAME, _VER_MAJ, _VER_MIN, _VER_BUILD, _VER_SUB = _seed.pick(_MSSQL_RELEASES)


def _build_prelogin_response() -> bytes:
    """TDS PRELOGIN response. Version option carries
    major(1) minor(1) build(2, network order) subbuild(2, network order)."""
    version_data = (
        bytes([_VER_MAJ & 0xff, _VER_MIN & 0xff])
        + struct.pack(">H", _VER_BUILD & 0xffff)
        + struct.pack(">H", _VER_SUB & 0xffff)
    )
    # Option directory + data. Offsets are from start of directory.
    # Five options: VERSION, ENCRYPTION, INSTOPT, THREADID, MARS.
    # Data fields, in order:
    encryption = b"\x02"                 # NOT_SUP
    instopt = b"\x00"
    threadid = struct.pack("<I", _seed.rng.randint(100, 9000))
    mars = b"\x00"

    directory = b""
    data = b""
    # Directory header is 5 bytes per option + 1 terminator; compute offsets
    # from end of terminator.
    dir_size = 5 * 5 + 1
    running_offset = dir_size

    def add_option(token: int, chunk: bytes) -> None:
        nonlocal directory, data, running_offset
        directory += bytes([token]) + struct.pack(">H", running_offset) + struct.pack(">H", len(chunk))
        data += chunk
        running_offset += len(chunk)

    add_option(0x00, version_data)
    add_option(0x01, encryption)
    add_option(0x02, instopt)
    add_option(0x03, threadid)
    add_option(0x04, mars)
    directory += b"\xff"

    payload = directory + data
    total_len = 8 + len(payload)
    header = struct.pack(">BBHBBBB", 0x04, 0x01, total_len, 0x00, 0x00, 0x01, 0x00)
    return header + payload


_PRELOGIN_RESP = _build_prelogin_response()




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


def _tds_error_packet(message: str) -> bytes:
    msg_enc = message.encode("utf-16-le")
    # Token type 0xAA = ERROR, followed by length, error number, state, class, msg_len, msg
    token = (
        b"\xaa"
        + struct.pack("<H", 4 + 1 + 1 + 2 + len(msg_enc) + 1 + 1 + 1 + 1 + 4)
        + struct.pack("<I", 18456)   # SQL error number: login failed
        + b"\x01"                    # state
        + b"\x0e"                    # class
        + struct.pack("<H", len(message))
        + msg_enc
        + b"\x00"                    # server name length
        + b"\x00"                    # proc name length
        + struct.pack("<I", 1)       # line number
    )
    done = b"\xfd\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload = token + done
    header = struct.pack(">BBHBBBB", 0x04, 0x01, len(payload) + 8, 0x00, 0x00, 0x01, 0x00)
    return header + payload


class MSSQLProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
        self._buf = b""
        self._prelogin_done = False

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])

    def data_received(self, data):
        self._buf += data
        while len(self._buf) >= 8:
            pkt_type = self._buf[0]
            pkt_len = struct.unpack(">H", self._buf[2:4])[0]
            if pkt_len < 8:
                _log("unknown_packet", src=self._peer[0], pkt_type=hex(pkt_type))
                self._transport.close()
                self._buf = b""
                return
            if len(self._buf) < pkt_len:
                break
            payload = self._buf[8:pkt_len]
            self._buf = self._buf[pkt_len:]
            self._handle_packet(pkt_type, payload)
            if self._transport.is_closing():
                self._buf = b""
                break

    def _handle_packet(self, pkt_type: int, payload: bytes):
        if pkt_type == 0x12:  # Pre-login
            self._transport.write(_PRELOGIN_RESP)
            self._prelogin_done = True
        elif pkt_type == 0x10:  # Login7
            username = self._parse_login7_username(payload)
            _log("auth", src=self._peer[0], username=username)
            self._transport.write(_tds_error_packet("Login failed for user."))
            self._transport.close()
        else:
            _log("unknown_packet", src=self._peer[0], pkt_type=hex(pkt_type))
            self._transport.close()

    def _parse_login7_username(self, payload: bytes) -> str:
        try:
            # Login7 layout: fixed header 36 bytes, then offsets
            # Username offset at bytes 36-37, length at 38-39
            if len(payload) < 40:
                return "<short_packet>"
            offset = struct.unpack("<H", payload[36:38])[0]
            length = struct.unpack("<H", payload[38:40])[0]
            username = payload[offset:offset + length * 2].decode("utf-16-le", errors="replace")
            return username
        except Exception:
            return "<parse_error>"

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"MSSQL server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(MSSQLProtocol, "0.0.0.0", 1433)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
