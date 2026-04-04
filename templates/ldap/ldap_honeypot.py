#!/usr/bin/env python3
"""
LDAP honeypot.
Parses BER-encoded BindRequest messages, logs DN and password, returns an
invalidCredentials error. Logs all interactions as JSON.
"""

import asyncio
import json
import os
import socket
from datetime import datetime, timezone

HONEYPOT_NAME = os.environ.get("HONEYPOT_NAME", "ldapserver")
LOG_TARGET = os.environ.get("LOG_TARGET", "")


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
        "service": "ldap",
        "host": HONEYPOT_NAME,
        "event": event_type,
        **kwargs,
    }
    print(json.dumps(event), flush=True)
    _forward(event)


def _ber_length(data: bytes, pos: int):
    """Return (length, next_pos)."""
    b = data[pos]
    if b < 0x80:
        return b, pos + 1
    n = b & 0x7f
    length = int.from_bytes(data[pos + 1:pos + 1 + n], "big")
    return length, pos + 1 + n


def _ber_string(data: bytes, pos: int):
    """Skip tag byte, read BER length, return (string, next_pos)."""
    pos += 1  # skip tag
    length, pos = _ber_length(data, pos)
    return data[pos:pos + length].decode(errors="replace"), pos + length


def _parse_bind_request(msg: bytes):
    """Best-effort extraction of (dn, password) from a raw LDAPMessage."""
    try:
        pos = 0
        # LDAPMessage SEQUENCE
        assert msg[pos] == 0x30
        pos += 1
        _, pos = _ber_length(msg, pos)
        # messageID INTEGER
        assert msg[pos] == 0x02
        pos += 1
        id_len, pos = _ber_length(msg, pos)
        pos += id_len
        # BindRequest [APPLICATION 0]
        assert msg[pos] == 0x60
        pos += 1
        _, pos = _ber_length(msg, pos)
        # version INTEGER
        assert msg[pos] == 0x02
        pos += 1
        v_len, pos = _ber_length(msg, pos)
        pos += v_len
        # name LDAPDN (OCTET STRING)
        dn, pos = _ber_string(msg, pos)
        # authentication CHOICE — simple [0] OCTET STRING
        if msg[pos] == 0x80:
            pos += 1
            pw_len, pos = _ber_length(msg, pos)
            password = msg[pos:pos + pw_len].decode(errors="replace")
        else:
            password = "<sasl_or_unknown>"
        return dn, password
    except Exception:
        return "<parse_error>", "<parse_error>"


def _bind_error_response(message_id: int) -> bytes:
    # BindResponse: resultCode=49 (invalidCredentials), matchedDN="", errorMessage=""
    result_code = bytes([0x0a, 0x01, 0x31])   # ENUMERATED 49
    matched_dn = bytes([0x04, 0x00])           # empty OCTET STRING
    error_msg  = bytes([0x04, 0x00])           # empty OCTET STRING
    bind_resp_body = result_code + matched_dn + error_msg
    bind_resp = bytes([0x61, len(bind_resp_body)]) + bind_resp_body

    msg_id_enc = bytes([0x02, 0x01, message_id & 0xff])
    ldap_msg_body = msg_id_enc + bind_resp
    return bytes([0x30, len(ldap_msg_body)]) + ldap_msg_body


class LDAPProtocol(asyncio.Protocol):
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
            if self._buf[0] != 0x30:
                self._buf = b""
                return
            if self._buf[1] < 0x80:
                msg_len = self._buf[1] + 2
            elif self._buf[1] == 0x81:
                if len(self._buf) < 3:
                    return
                msg_len = self._buf[2] + 3
            else:
                self._buf = b""
                return
            if len(self._buf) < msg_len:
                return
            msg = self._buf[:msg_len]
            self._buf = self._buf[msg_len:]
            self._handle_message(msg)

    def _handle_message(self, msg: bytes):
        # Extract messageID for the response
        try:
            message_id = msg[4] if len(msg) > 4 else 1
        except Exception:
            message_id = 1
        dn, password = _parse_bind_request(msg)
        _log("bind", src=self._peer[0], dn=dn, password=password)
        self._transport.write(_bind_error_response(message_id))

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"LDAP honeypot starting as {HONEYPOT_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(LDAPProtocol, "0.0.0.0", 389)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
