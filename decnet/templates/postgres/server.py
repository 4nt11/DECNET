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

import instance_seed as _seed
import base64 as _base64
from syslog_bridge import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "pgserver")
SERVICE_NAME   = "postgres"
LOG_TARGET = os.environ.get("LOG_TARGET", "")
PORT = int(os.environ.get("PORT", "5432"))

# Per-instance list of "existing" databases. A real server knows which dbs
# it hosts and returns SQLSTATE 3D000 "database does not exist" for anything
# else — refusing with "password authentication failed" for every single
# probe is a strong honeypot signal.
_BASE_DBS = {"postgres", "template0", "template1"}
_APP_DB_CHOICES = [
    ["app", "app_prod"],
    ["webapp", "sessions"],
    ["erp", "erp_hist"],
    ["django", "django_cache"],
    ["rails_production"],
    ["wordpress"],
    ["gitlabhq_production"],
    ["metrics", "grafana"],
]
_DATABASES = _BASE_DBS | set(_seed.pick(_APP_DB_CHOICES))


def _error_response(severity: str, sqlstate: str, message: str) -> bytes:
    """Wire-level PG ErrorResponse. Fields: S (localized severity), V
    (non-localized severity, PG 9.6+), C (SQLSTATE), M (message)."""
    body = (
        b"S" + severity.encode() + b"\x00"
        + b"V" + severity.encode() + b"\x00"
        + b"C" + sqlstate.encode() + b"\x00"
        + b"M" + message.encode() + b"\x00"
        + b"\x00"
    )
    return b"E" + struct.pack(">I", len(body) + 4) + body




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
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
        database = params.get("database", "") or username
        self._username = username
        self._database = database
        _log("startup", src=self._peer[0], username=username, database=database)
        # If the requested DB doesn't exist on this instance, real Postgres
        # rejects *before* asking for a password. Short-circuit so the decoy
        # matches that behavior and exposes the per-decky DB list.
        if database and database not in _DATABASES:
            msg = f'database "{database}" does not exist'
            self._transport.write(_error_response("FATAL", "3D000", msg))
            self._transport.close()
            return
        self._state = "auth"
        salt = os.urandom(4)
        auth_md5 = b"R" + struct.pack(">I", 12) + struct.pack(">I", 5) + salt
        self._transport.write(auth_md5)

    def _handle_password(self, payload: bytes):
        # Postgres MD5 challenge-response: the wire form is the literal
        # ASCII string "md5" + 32 hex chars (md5(md5(pw+user)+salt)).
        # Plaintext is unrecoverable, so we land this in the Credential
        # table as secret_kind="postgres_md5_challenge" — secret_b64
        # carries the raw hash bytes (after stripping the "md5" prefix
        # and hex-decoding) for content-addressable reuse within-kind.
        pw_hash = payload.rstrip(b"\x00").decode(errors="replace")
        _hex = pw_hash[3:] if pw_hash.startswith("md5") else pw_hash
        try:
            _raw = bytes.fromhex(_hex)
        except ValueError:
            _raw = _hex.encode("utf-8", errors="replace")
        _b64 = _base64.b64encode(_raw).decode("ascii")
        _user = getattr(self, "_username", "")
        _log("auth", src=self._peer[0],
             username=_user, principal=_user,
             database=getattr(self, "_database", ""),
             pw_hash=pw_hash,
             secret_kind="postgres_md5_challenge",
             secret_printable=pw_hash,
             secret_b64=_b64)
        user = getattr(self, "_username", "")
        msg = f'password authentication failed for user "{user}"'
        _seed.jitter_sync(20, 90)
        self._transport.write(_error_response("FATAL", "28P01", msg))
        self._transport.close()

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"PostgreSQL server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(PostgresProtocol, "0.0.0.0", PORT)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
