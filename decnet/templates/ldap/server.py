#!/usr/bin/env python3
"""
LDAPserver.
Parses BER-encoded BindRequest messages, logs DN and password, returns an
invalidCredentials error. Logs all interactions as JSON.
"""

import asyncio
import os
import re

import instance_seed as _seed
from syslog_bridge import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "ldapserver")
SERVICE_NAME   = "ldap"
LOG_TARGET = os.environ.get("LOG_TARGET", "")

# RFC 4514 distinguished-name grammar: DN is a sequence of comma-separated
# RDNs like "cn=foo,ou=people,dc=example,dc=com". Each RDN is
# attribute=value, attribute matches [A-Za-z][A-Za-z0-9-]*. We keep this
# check loose on value contents (commas can be escaped etc.) but tight on
# shape, so garbage like `"abc"` or `\x00\x00` gets rejected with
# invalidDNSyntax (34) instead of invalidCredentials (49) — that's how a
# real OpenLDAP replies.
_RDN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*=.+$")


def _is_valid_dn(dn: str) -> bool:
    """True for empty (anonymous bind) or RFC 4514-shaped DN."""
    if dn == "":
        return True
    if len(dn) > 1024:
        return False
    # Split on unescaped commas. Not perfect, but catches the obvious
    # "not a DN" inputs (missing '=' in some RDN, empty segments, etc.).
    parts: list[str] = []
    buf = ""
    escape = False
    for ch in dn:
        if escape:
            buf += ch
            escape = False
            continue
        if ch == "\\":
            buf += ch
            escape = True
            continue
        if ch == ",":
            parts.append(buf)
            buf = ""
            continue
        buf += ch
    parts.append(buf)
    return all(_RDN_RE.match(p.strip()) for p in parts)




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


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
        assert msg[pos] == 0x30  # nosec B101
        pos += 1
        _, pos = _ber_length(msg, pos)
        # messageID INTEGER
        assert msg[pos] == 0x02  # nosec B101
        pos += 1
        id_len, pos = _ber_length(msg, pos)
        pos += id_len
        # BindRequest [APPLICATION 0]
        assert msg[pos] == 0x60  # nosec B101
        pos += 1
        _, pos = _ber_length(msg, pos)
        # version INTEGER
        assert msg[pos] == 0x02  # nosec B101
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
            password = "<sasl_or_unknown>"  # nosec B105
        return dn, password
    except Exception:
        return "<parse_error>", "<parse_error>"


def _bind_error_response(message_id: int, result_code: int = 49, error_text: str = "") -> bytes:
    """BindResponse with a configurable resultCode + diagnosticMessage.
    49 = invalidCredentials, 34 = invalidDNSyntax, 53 = unwillingToPerform."""
    err_bytes = error_text.encode()
    result_enc = bytes([0x0a, 0x01, result_code & 0xff])
    matched_dn = bytes([0x04, 0x00])
    error_msg  = bytes([0x04, len(err_bytes)]) + err_bytes
    bind_resp_body = result_enc + matched_dn + error_msg
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
        _seed.jitter_sync(10, 60)
        if dn and not _is_valid_dn(dn):
            # OpenLDAP returns invalidDNSyntax (34) for malformed DNs, with
            # a diagnostic like: "invalid DN syntax". Matching that exactly
            # keeps the decoy consistent with what a scanner expects.
            self._transport.write(_bind_error_response(
                message_id, result_code=34,
                error_text="invalid DN"
            ))
        else:
            self._transport.write(_bind_error_response(message_id))

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"LDAP server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(LDAPProtocol, "0.0.0.0", 389)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
