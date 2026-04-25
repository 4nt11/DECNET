#!/usr/bin/env python3
"""Minimal honeypot RDP server (X.224 cookie + protocol negotiation).

Parses the very first packet of every RDP connection — the X.224
Connection Request — and extracts:

* The ``mstshash=<user>`` routing cookie that mstsc, FreeRDP, ncrack,
  Hydra, and Metasploit's ``rdp_login`` all stamp into the CR. This is
  the only piece of credential information that flows in plaintext on
  the wire when the attacker speaks RDP, so capturing it is the
  highest-value-per-byte signal we can extract without going down the
  Standard-RDP-Security RC4 rabbit hole or the TLS+CredSSP stack.
* The ``rdpNegRequest.requestedProtocols`` flags, which tell us
  whether the client asked for legacy RDP, SSL/TLS, or NLA/CredSSP.

We always answer with a valid X.224 Connection Confirm selecting
``PROTOCOL_RDP`` (legacy / Standard RDP Security). The connection is
then closed cleanly. NLA / CredSSP credential capture is the job of
the ``RDP_ENABLE_NLA`` path, landed alongside this in DEBT-040.

References:
- MS-RDPBCGR §2.2.1.1 Client X.224 Connection Request PDU
- MS-RDPBCGR §2.2.1.2 Server X.224 Connection Confirm PDU
- RFC 1006 (TPKT) §6
"""

from __future__ import annotations

import asyncio
import os
import re

from syslog_bridge import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "WORKSTATION")
SERVICE_NAME = "rdp"
LOG_TARGET = os.environ.get("LOG_TARGET", "")

LISTEN_HOST = "0.0.0.0"  # nosec B104 — honeypot binds all interfaces by design
LISTEN_PORT = 3389

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


# ── Connection handler ───────────────────────────────────────────────────────


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
        # Confirm with PROTOCOL_RDP. PROTOCOL_SSL / PROTOCOL_HYBRID
        # selection arrives with the NLA path in a follow-up commit.
        writer.write(_build_x224_cc(PROTOCOL_RDP))
        await writer.drain()
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
