#!/usr/bin/env python3
"""Minimal honeypot RDP server.

Two operating modes share the same X.224 Connection Request parser:

1. **Default (basic).** Parse the X.224 CR, extract the ``mstshash``
   routing cookie + ``rdpNegRequest.requestedProtocols`` flags, answer
   with a Connection Confirm selecting ``PROTOCOL_RDP``, close.
   Captures the username most attackers leak in plaintext.

2. **NLA (``RDP_ENABLE_NLA=true``).** Confirm ``PROTOCOL_HYBRID``,
   upgrade the socket to TLS, then read inbound CredSSP TSRequest DER
   blobs. We do not parse the ASN.1 — we just scan for the NTLMSSP
   signature inside the TLS-decrypted plaintext (CredSSP wraps a
   handful of NTLMSSP messages); when the inbound message is a
   Type 3, ``parse_type3()`` produces the universal credential SD
   block and we land an NTLMv2 hash in the Credential table. The
   server responds to Type 1 with a hand-built TSRequest carrying an
   NTLMSSP Type 2 challenge, then drops after Type 3.

References:
- MS-RDPBCGR §2.2.1.1 Client X.224 Connection Request PDU
- MS-RDPBCGR §2.2.1.2 Server X.224 Connection Confirm PDU
- MS-CSSP §2.2.1 TSRequest
- MS-NLMP §2.2.1.2 NTLMSSP CHALLENGE_MESSAGE
- RFC 1006 (TPKT) §6
"""

from __future__ import annotations

import asyncio
import os
import re
import ssl
import struct

import instance_seed
from ntlmssp import find_ntlmssp, parse_type3
from syslog_bridge import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "WORKSTATION")
SERVICE_NAME = "rdp"
LOG_TARGET = os.environ.get("LOG_TARGET", "")
ENABLE_NLA = os.environ.get("RDP_ENABLE_NLA", "").lower() in ("1", "true", "yes")
TLS_CERT = os.environ.get("TLS_CERT", "/opt/tls/cert.pem")
TLS_KEY = os.environ.get("TLS_KEY", "/opt/tls/key.pem")

LISTEN_HOST = "0.0.0.0"  # nosec B104 — honeypot binds all interfaces by design
LISTEN_PORT = 3389

# Per-instance NTLM challenge: deterministic-per-decky-but-different-
# across-the-fleet (see instance_seed module docstring). A fixed
# challenge across the fleet would let scanners fingerprint us.
SERVER_CHALLENGE = instance_seed.random_bytes(8, "ntlm_challenge")

MAX_TSREQUEST_LEN = 32 * 1024  # CredSSP messages are small; cap memory pressure

# X.224 / TPKT constants
TPKT_VERSION = 0x03
X224_CR = 0xE0  # Connection Request
X224_CC = 0xD0  # Connection Confirm

# rdpNegRequest / Response (MS-RDPBCGR §2.2.1.1.1 / §2.2.1.2.1)
TYPE_RDP_NEG_REQ = 0x01
TYPE_RDP_NEG_RSP = 0x02

PROTOCOL_RDP = 0x00000000
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002

MAX_TPKT_LEN = 8 * 1024  # CR PDUs are tiny; cap to avoid attacker memory pressure

_COOKIE_RE = re.compile(rb"Cookie:\s*mstshash=([^\r\n\x00]{1,256})\r\n", re.IGNORECASE)


def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


# ── PDU helpers ───────────────────────────────────────────────────────────────


def _parse_tpkt(buf: bytes) -> bytes | None:
    """Return the X.224 payload from a single TPKT, or None if malformed."""
    if len(buf) < 4 or buf[0] != TPKT_VERSION:
        return None
    total_len = int.from_bytes(buf[2:4], "big")
    if total_len < 7 or total_len > MAX_TPKT_LEN or total_len > len(buf):
        return None
    return buf[4:total_len]


def _parse_x224_cr(x224: bytes) -> tuple[str | None, int]:
    """Return (mstshash_cookie, requested_protocols).

    Cookie is None when absent. requested_protocols is 0 when no
    rdpNegRequest is included.
    """
    if len(x224) < 7 or x224[1] != X224_CR:
        return None, 0
    # x224[0] = LI (length indicator), x224[1] = CR code (TPDU type)
    # Variable part follows the fixed 7-byte header. Cookie is ASCII
    # text terminated by CRLF; rdpNegRequest is the next 8 bytes.
    var = x224[7:]
    cookie_match = _COOKIE_RE.search(var)
    cookie = None
    if cookie_match:
        try:
            cookie = cookie_match.group(1).decode("ascii", errors="replace")
        except Exception:  # noqa: BLE001
            cookie = None
    # rdpNegRequest sits after the cookie's CRLF. Locate by signature
    # rather than offset since cookie length varies.
    requested = 0
    neg = var
    if cookie_match:
        neg = var[cookie_match.end():]
    if len(neg) >= 8 and neg[0] == TYPE_RDP_NEG_REQ:
        # Type(1) Flags(1) Length(2 LE) RequestedProtocols(4 LE)
        requested = int.from_bytes(neg[4:8], "little")
    return cookie, requested


def _build_x224_cc(selected_protocol: int = PROTOCOL_RDP) -> bytes:
    """Build a TPKT-wrapped X.224 Connection Confirm with rdpNegRsp."""
    # rdpNegResponse: Type(1)=0x02 Flags(1)=0x00 Length(2 LE)=0x0008
    #                 SelectedProtocol(4 LE)
    neg_rsp = bytes([TYPE_RDP_NEG_RSP, 0x00]) + (8).to_bytes(2, "little") + selected_protocol.to_bytes(4, "little")
    # X.224 CC fixed header: LI=0x0E (14 bytes follow), CC=0xD0,
    # DST_REF=0, SRC_REF=0x1234 (any), CLASS=0x00
    x224 = bytes([0x0E, X224_CC, 0x00, 0x00, 0x12, 0x34, 0x00]) + neg_rsp
    tpkt = bytes([TPKT_VERSION, 0x00]) + (4 + len(x224)).to_bytes(2, "big")
    return tpkt + x224


# ── NLA / CredSSP helpers ────────────────────────────────────────────────────


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_read_len(buf: bytes, off: int) -> tuple[int, int]:
    """Return (length, new_offset) reading a DER length field."""
    if off >= len(buf):
        return 0, off
    first = buf[off]
    off += 1
    if first < 0x80:
        return first, off
    n = first & 0x7F
    if n == 0 or off + n > len(buf):
        return 0, off
    val = int.from_bytes(buf[off:off + n], "big")
    return val, off + n


def _build_ntlmssp_type2(challenge: bytes) -> bytes:
    """Build a minimal NTLMSSP CHALLENGE_MESSAGE (MS-NLMP §2.2.1.2).

    Mirrors the SMB framer's builder. Inlined here rather than shared so
    that ``_shared/ntlmssp.py`` stays a pure parser module.
    """
    target = "WORKGROUP".encode("utf-16-le")
    av_name = "WORKGROUP".encode("utf-16-le")
    target_info = struct.pack("<HH", 1, len(av_name)) + av_name + struct.pack("<HH", 0, 0)
    flags = 0x00828201  # UNICODE | NTLM | TARGET_INFO | always_sign
    target_off = 56
    info_off = target_off + len(target)
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 2)
        + struct.pack("<HHI", len(target), len(target), target_off)
        + struct.pack("<I", flags)
        + challenge
        + b"\x00" * 8
        + struct.pack("<HHI", len(target_info), len(target_info), info_off)
        + b"\x00" * 8
        + target + target_info
    )


def _build_tsrequest_with_token(version: int, ntlm_blob: bytes) -> bytes:
    """Build a CredSSP TSRequest carrying a single negoToken (MS-CSSP §2.2.1).

    Layout (DER, simplified — only fields we need on the response path):

        TSRequest ::= SEQUENCE {
            version    [0] INTEGER,
            negoTokens [1] SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
        }
    """
    # version [0] INTEGER
    version_bytes = version.to_bytes(1, "big")
    version_field = b"\x02" + _der_len(len(version_bytes)) + version_bytes
    version_tagged = b"\xa0" + _der_len(len(version_field)) + version_field

    # innermost: negoToken [0] OCTET STRING
    octet = b"\x04" + _der_len(len(ntlm_blob)) + ntlm_blob
    negotoken_tagged = b"\xa0" + _der_len(len(octet)) + octet
    inner_seq = b"\x30" + _der_len(len(negotoken_tagged)) + negotoken_tagged
    outer_seq = b"\x30" + _der_len(len(inner_seq)) + inner_seq
    negotokens_tagged = b"\xa1" + _der_len(len(outer_seq)) + outer_seq

    body = version_tagged + negotokens_tagged
    return b"\x30" + _der_len(len(body)) + body


async def _read_one_tsrequest(reader: asyncio.StreamReader) -> bytes:
    """Read one DER-encoded TSRequest (outer SEQUENCE) from the stream.

    A SEQUENCE starts with tag 0x30 followed by a DER length, then that
    many content bytes. We bound the total to MAX_TSREQUEST_LEN.
    """
    tag = await reader.readexactly(1)
    if tag != b"\x30":
        raise ValueError("not a SEQUENCE")
    first_len = (await reader.readexactly(1))[0]
    if first_len < 0x80:
        body_len = first_len
        len_bytes = bytes([first_len])
    else:
        n = first_len & 0x7F
        if n == 0 or n > 4:
            raise ValueError("bad DER length")
        ext = await reader.readexactly(n)
        body_len = int.from_bytes(ext, "big")
        len_bytes = bytes([first_len]) + ext
    if body_len > MAX_TSREQUEST_LEN:
        raise ValueError("TSRequest too large")
    body = await reader.readexactly(body_len)
    return tag + len_bytes + body


async def _handle_nla(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    src_ip: str,
    src_port: int,
) -> None:
    """Drive the CredSSP exchange post-TLS-handshake.

    Reads up to 3 inbound TSRequests; on the one carrying an NTLMSSP
    Type 3, emits the credential and closes.
    """
    for round_no in range(3):
        try:
            ts_blob = await asyncio.wait_for(_read_one_tsrequest(reader), timeout=10.0)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError):
            return
        off = find_ntlmssp(ts_blob)
        if off < 0:
            return
        ntlm = ts_blob[off:]
        # Message type at offset 8 (after the 8-byte signature)
        if len(ntlm) < 12:
            return
        msg_type = struct.unpack_from("<I", ntlm, 8)[0]
        if msg_type == 1:
            # Type 1 → respond with TSRequest carrying Type 2 challenge
            type2 = _build_ntlmssp_type2(SERVER_CHALLENGE)
            resp = _build_tsrequest_with_token(version=6, ntlm_blob=type2)
            writer.write(resp)
            await writer.drain()
            continue
        if msg_type == 3:
            # Type 3 → credential lands here
            cred = parse_type3(ntlm)
            if cred:
                _log(
                    "auth_attempt",
                    src_ip=src_ip,
                    src_port=src_port,
                    auth_path="nla",
                    **cred,
                )
            return
        # Unknown type → drop
        return


# ── Connection handler ───────────────────────────────────────────────────────


def _build_tls_context() -> ssl.SSLContext | None:
    """Load the per-decky self-signed cert for the NLA path.

    Returns None if the cert files aren't present yet (allows the
    container to come up even before the entrypoint has generated
    them; subsequent connections retry).
    """
    if not (os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY)):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
    # CredSSP clients negotiate down — accept whatever the client offers
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


async def _upgrade_to_tls_and_capture(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    src_ip: str,
    src_port: int,
) -> None:
    """Upgrade the underlying socket to TLS, then run the CredSSP loop."""
    ctx = _build_tls_context()
    if ctx is None:
        _log("error", severity=4, src_ip=src_ip, msg="TLS cert missing; NLA path unavailable")
        return
    transport = writer.transport
    loop = asyncio.get_running_loop()
    try:
        new_transport = await loop.start_tls(
            transport,
            transport.get_protocol(),
            ctx,
            server_side=True,
        )
    except (ssl.SSLError, OSError) as exc:
        _log("tls_handshake_failed", severity=4, src_ip=src_ip, msg=str(exc))
        return
    # Rewrap the StreamReader/StreamWriter on top of the new TLS transport.
    # We use the stdlib's protocol to bridge the upgraded transport back
    # into a StreamReader/StreamWriter pair the rest of the handler can use.
    new_reader = asyncio.StreamReader(loop=loop)
    new_protocol = asyncio.StreamReaderProtocol(new_reader, loop=loop)
    new_transport.set_protocol(new_protocol)
    new_protocol.connection_made(new_transport)
    new_writer = asyncio.StreamWriter(new_transport, new_protocol, new_reader, loop)
    await _handle_nla(new_reader, new_writer, src_ip, src_port)


async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    src_ip, src_port = peer[0], peer[1]
    _log("connection", src_ip=src_ip, src_port=src_port)
    try:
        # Read TPKT header (4 bytes), then the rest of the PDU
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
        if hdr[0] != TPKT_VERSION:
            return
        total_len = int.from_bytes(hdr[2:4], "big")
        if total_len < 7 or total_len > MAX_TPKT_LEN:
            return
        rest = await asyncio.wait_for(reader.readexactly(total_len - 4), timeout=5.0)
        x224 = _parse_tpkt(hdr + rest)
        if x224 is None:
            return
        cookie, requested = _parse_x224_cr(x224)
        fields: dict = {
            "src_ip": src_ip,
            "src_port": src_port,
            "requested_protocols": requested,
        }
        if cookie:
            fields["username"] = cookie
            fields["principal"] = cookie
            _log("rdp_cookie", **fields)
        else:
            _log("connection_request", **fields)

        nla_path = ENABLE_NLA and (requested & PROTOCOL_HYBRID)
        selected = PROTOCOL_HYBRID if nla_path else PROTOCOL_RDP
        writer.write(_build_x224_cc(selected))
        await writer.drain()
        if nla_path:
            await _upgrade_to_tls_and_capture(reader, writer, src_ip, src_port)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        pass
    except Exception as exc:  # noqa: BLE001 — honeypot must never crash the worker
        _log("error", severity=4, src_ip=src_ip, msg=str(exc))
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        _log("disconnect", src_ip=src_ip, src_port=src_port)


async def _main() -> None:
    _log("startup", msg=f"RDP server starting as {NODE_NAME} on port {LISTEN_PORT}")
    server = await asyncio.start_server(_handle_client, LISTEN_HOST, LISTEN_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        _log("shutdown")
