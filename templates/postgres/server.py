#!/usr/bin/env python3
"""
PostgreSQLserver.
Reads the startup message, extracts username and database, responds with
an AuthenticationMD5Password challenge, logs the hash sent back, then
returns an error. Logs all interactions as JSON.
"""

import asyncio
import os
import struct
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "pgserver")
SERVICE_NAME   = "postgres"
LOG_TARGET = os.environ.get("LOG_TARGET", "")
def _error_response(message: str) -> bytes:
    body = b"S" + b"FATAL\x00" + b"M" + message.encode() + b"\x00\x00"
    return b"E" + struct.pack(">I", len(body) + 4) + body




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    print(line, flush=True)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


class PostgresProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
        self._buf = b""
        self._state = "startup"

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])

    def data_received(self, data):
        self._buf += data
        self._process()

    def _process(self):
        if self._state == "startup":
            if len(self._buf) < 4:
                return
            msg_len = struct.unpack(">I", self._buf[:4])[0]
            if msg_len < 8 or msg_len > 10_000:
                self._transport.close()
                self._buf = b""
                return
            if len(self._buf) < msg_len:
                return
            msg = self._buf[:msg_len]
            self._buf = self._buf[msg_len:]
            self._handle_startup(msg)
        elif self._state == "auth":
            if len(self._buf) < 5:
                return
            msg_type = chr(self._buf[0])
            msg_len = struct.unpack(">I", self._buf[1:5])[0]
            if msg_len < 4 or msg_len > 10_000:
                self._transport.close()
                self._buf = b""
                return
            if len(self._buf) < msg_len + 1:
                return
            payload = self._buf[5:msg_len + 1]
            self._buf = self._buf[msg_len + 1:]
            if msg_type == "p":
                self._handle_password(payload)

    def _handle_startup(self, msg: bytes):
        # Startup message: length(4) + protocol_version(4) + params (key=value\0 pairs)
        if len(msg) < 8:
            return
        proto = struct.unpack(">I", msg[4:8])[0]
        if proto == 80877103:  # SSL request
            self._transport.write(b"N")  # reject SSL
            return
        params_raw = msg[8:].split(b"\x00")
        params = {}
        for i in range(0, len(params_raw) - 1, 2):
            k = params_raw[i].decode(errors="replace")
            v = params_raw[i + 1].decode(errors="replace") if i + 1 < len(params_raw) else ""
            if k:
                params[k] = v
        username = params.get("user", "")
        database = params.get("database", "")
        _log("startup", src=self._peer[0], username=username, database=database)
        self._state = "auth"
        salt = os.urandom(4)
        auth_md5 = b"R" + struct.pack(">I", 12) + struct.pack(">I", 5) + salt
        self._transport.write(auth_md5)

    def _handle_password(self, payload: bytes):
        pw_hash = payload.rstrip(b"\x00").decode(errors="replace")
        _log("auth", src=self._peer[0], pw_hash=pw_hash)
        self._transport.write(_error_response("password authentication failed"))
        self._transport.close()

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"PostgreSQL server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(PostgresProtocol, "0.0.0.0", 5432)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
