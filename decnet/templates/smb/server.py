#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Minimal honeypot SMB2 server.

Hand-rolled asyncio framer that does just enough of MS-SMB2 to lure a
client through Negotiate → Session Setup (Type1) → Session Setup
(Type3), at which point we extract the inner NTLMSSP Type 3 with the
shared :func:`ntlmssp.parse_type3` parser and emit a credential SD
block. Authentication always fails with STATUS_LOGON_FAILURE — the
attacker's hash lands in the Credential table; the attacker does not
land on the host.

References:
- MS-SMB2 §2.2.3 NEGOTIATE Request, §2.2.4 NEGOTIATE Response
- MS-SMB2 §2.2.5 SESSION_SETUP Request, §2.2.6 SESSION_SETUP Response
- MS-NLMP §2.2.1 NTLMSSP messages (CHALLENGE_MESSAGE Type 2)
- RFC 1002 §4.3 NetBIOS Session Service framing
"""

from __future__ import annotations

import asyncio
import os
import struct

import instance_seed
from ntlmssp import find_ntlmssp, parse_type3
from syslog_bridge import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "WORKSTATION")
SERVICE_NAME = "smb"
LOG_TARGET = os.environ.get("LOG_TARGET", "")

LISTEN_HOST = "0.0.0.0"  # nosec B104 — honeypot binds all interfaces by design
LISTEN_PORT = 445

# SMB2 status codes
STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
STATUS_LOGON_FAILURE = 0xC000006D

# SMB2 commands
SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001

SMB2_MAGIC = b"\xfeSMB"
NBSS_SESSION_MESSAGE = 0x00

# Per-instance NTLM challenge: deterministic-per-decky-but-different-
# across-the-fleet. Derived from NODE_NAME so two captures from the
# same decky reuse the same challenge (lets offline attackers retry
# wordlists), while every decky in the fleet differs (looks like a
# real population of hosts to a scanner).
SERVER_CHALLENGE = instance_seed.random_bytes(8, "ntlm_challenge")
SERVER_GUID = instance_seed.random_bytes(16, "smb_server_guid")

# Read caps; an attacker shouldn't be able to make us allocate
# unbounded memory just by lying about NetBIOS frame length.
MAX_NBSS_LEN = 1 * 1024 * 1024  # 1 MiB is plenty for SessionSetup blobs


def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


# ── SPNEGO / NTLMSSP Type 2 builder ──────────────────────────────────────────


def _build_ntlmssp_type2(challenge: bytes) -> bytes:
    """Build a minimal NTLMSSP CHALLENGE_MESSAGE (MS-NLMP §2.2.1.2).

    Layout (all little-endian):
      0   "NTLMSSP\\0"          8 bytes
      8   MessageType=2         u32
     12   TargetNameFields      8 bytes (Len, MaxLen, Offset)
     20   NegotiateFlags        u32
     24   ServerChallenge       8 bytes
     32   Reserved              8 bytes
     40   TargetInfoFields      8 bytes
     48   Version               8 bytes
     56   Payload               TargetName + TargetInfo

    We advertise NEGOTIATE_UNICODE | NEGOTIATE_NTLM | NEGOTIATE_TARGET_INFO
    (0x00828201) which is what real Windows servers send in practice; the
    attacker's client uses these flags to decide whether to send Unicode
    field strings in its Type 3 — the parser handles either.
    """
    target = "WORKGROUP".encode("utf-16-le")
    # AV pair list: NetBIOS computer name + EOL terminator
    av_name = "WORKGROUP".encode("utf-16-le")
    target_info = struct.pack("<HH", 1, len(av_name)) + av_name + struct.pack("<HH", 0, 0)

    flags = 0x00828201  # UNICODE | NTLM | TARGET_INFO | always_sign
    payload = target + target_info
    target_off = 56
    info_off = target_off + len(target)

    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 2)  # Type 2
        + struct.pack("<HHI", len(target), len(target), target_off)
        + struct.pack("<I", flags)
        + challenge
        + b"\x00" * 8  # reserved
        + struct.pack("<HHI", len(target_info), len(target_info), info_off)
        + b"\x00" * 8  # version
        + payload
    )


def _wrap_spnego_type2(ntlm_type2: bytes) -> bytes:
    """SPNEGO NegTokenResp DER carrying the NTLMSSP Type 2 blob.

    Real Windows wraps Type 2 in an SPNEGO NegTokenResp (RFC 4178). A
    well-formed wrapping is rarely required by attacker tools (Hydra,
    Metasploit's smb_login, Impacket scanners all accept a raw Type 2
    too) — but we ship the SPNEGO envelope so that finicky clients
    don't bail out before sending Type 3, which is what we actually
    want on the wire. The DER below hand-encodes a single
    ``NegTokenResp`` with negState=accept-incomplete, supportedMech =
    NTLMSSP OID, and responseToken = ntlm_type2.
    """
    # NTLMSSP OID = 1.3.6.1.4.1.311.2.2.10 → DER bytes
    ntlmssp_oid = bytes.fromhex("06 0a 2b 06 01 04 01 82 37 02 02 0a".replace(" ", ""))
    # negState [0] enum 1 (accept-incomplete)
    neg_state = bytes.fromhex("a0 03 0a 01 01".replace(" ", ""))
    # supportedMech [1] OID
    supported = b"\xa1" + _der_len(len(ntlmssp_oid)) + ntlmssp_oid
    # responseToken [2] OCTET STRING
    rt_inner = b"\x04" + _der_len(len(ntlm_type2)) + ntlm_type2
    response_token = b"\xa2" + _der_len(len(rt_inner)) + rt_inner
    inner = neg_state + supported + response_token
    neg_token_resp = b"\x30" + _der_len(len(inner)) + inner  # SEQUENCE
    # NegTokenResp is itself tagged [1] in the outer choice
    return b"\xa1" + _der_len(len(neg_token_resp)) + neg_token_resp


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


# ── SMB2 PDU helpers ─────────────────────────────────────────────────────────


def _smb2_header(command: int, status: int, message_id: int, session_id: int = 0) -> bytes:
    """SMB2 sync header (64 bytes), MS-SMB2 §2.2.1."""
    return (
        SMB2_MAGIC                          # ProtocolId
        + struct.pack("<H", 64)             # StructureSize
        + struct.pack("<H", 0)              # CreditCharge
        + struct.pack("<I", status)         # Status
        + struct.pack("<H", command)        # Command
        + struct.pack("<H", 1)              # CreditResponse
        + struct.pack("<I", 0x00000001)     # Flags = SERVER_TO_REDIR
        + struct.pack("<I", 0)              # NextCommand
        + struct.pack("<Q", message_id)     # MessageId
        + struct.pack("<I", 0)              # Reserved (sync)
        + struct.pack("<I", 0)              # TreeId
        + struct.pack("<Q", session_id)     # SessionId
        + b"\x00" * 16                      # Signature
    )


def _negotiate_response(message_id: int) -> bytes:
    """SMB2 NEGOTIATE response (MS-SMB2 §2.2.4) — dialect 0x0210 (SMB 2.1)."""
    body = (
        struct.pack("<H", 65)               # StructureSize
        + struct.pack("<H", 0)              # SecurityMode
        + struct.pack("<H", 0x0210)         # DialectRevision = SMB 2.1
        + struct.pack("<H", 0)              # Reserved
        + SERVER_GUID
        + struct.pack("<I", 0)              # Capabilities
        + struct.pack("<I", 0x00010000)     # MaxTransactSize
        + struct.pack("<I", 0x00010000)     # MaxReadSize
        + struct.pack("<I", 0x00010000)     # MaxWriteSize
        + struct.pack("<Q", 0)              # SystemTime
        + struct.pack("<Q", 0)              # ServerStartTime
        + struct.pack("<H", 128)            # SecurityBufferOffset (header64+body64)
        + struct.pack("<H", 0)              # SecurityBufferLength
        + struct.pack("<I", 0)              # Reserved2
    )
    return _smb2_header(SMB2_NEGOTIATE, STATUS_SUCCESS, message_id) + body


def _session_setup_response(message_id: int, session_id: int, sec_blob: bytes, status: int) -> bytes:
    """SMB2 SESSION_SETUP response (MS-SMB2 §2.2.6) carrying SPNEGO blob."""
    body = (
        struct.pack("<H", 9)                # StructureSize
        + struct.pack("<H", 0)              # SessionFlags
        + struct.pack("<H", 64 + 8)         # SecurityBufferOffset
        + struct.pack("<H", len(sec_blob))  # SecurityBufferLength
    )
    return _smb2_header(SMB2_SESSION_SETUP, status, message_id, session_id) + body + sec_blob


# ── Connection handler ───────────────────────────────────────────────────────


async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    src_ip, src_port = peer[0], peer[1]
    _log("connection", src_ip=src_ip, src_port=src_port)
    session_id = 0x1000_0000_0000_0001
    setup_round = 0
    try:
        while True:
            # NetBIOS Session Service framing: 1 type byte + 3 length bytes
            hdr = await reader.readexactly(4)
            if hdr[0] != NBSS_SESSION_MESSAGE:
                # Session Request / Keepalive / etc — quietly drop.
                break
            nb_len = int.from_bytes(hdr[1:4], "big")
            if nb_len < 64 or nb_len > MAX_NBSS_LEN:
                break
            pdu = await reader.readexactly(nb_len)
            if not pdu.startswith(SMB2_MAGIC):
                # SMB1 Negotiate or other — not implemented; drop.
                break
            command = struct.unpack_from("<H", pdu, 12)[0]
            message_id = struct.unpack_from("<Q", pdu, 24)[0]
            if command == SMB2_NEGOTIATE:
                resp = _negotiate_response(message_id)
                _send_nbss(writer, resp)
            elif command == SMB2_SESSION_SETUP:
                setup_round += 1
                # Body starts after 64-byte header; parse SecurityBufferOffset/Length
                if len(pdu) < 64 + 24:
                    break
                sec_off = struct.unpack_from("<H", pdu, 64 + 12)[0]
                sec_len = struct.unpack_from("<H", pdu, 64 + 14)[0]
                blob = pdu[sec_off:sec_off + sec_len] if sec_len else b""
                if setup_round == 1:
                    # First Session Setup → respond with NTLMSSP Type 2
                    type2 = _build_ntlmssp_type2(SERVER_CHALLENGE)
                    spnego = _wrap_spnego_type2(type2)
                    resp = _session_setup_response(
                        message_id, session_id, spnego, STATUS_MORE_PROCESSING_REQUIRED
                    )
                    _send_nbss(writer, resp)
                else:
                    # Second Session Setup → contains NTLMSSP Type 3
                    off = find_ntlmssp(blob)
                    if off >= 0:
                        cred = parse_type3(blob[off:])
                        if cred:
                            _log(
                                "auth_attempt",
                                src_ip=src_ip,
                                src_port=src_port,
                                **cred,
                            )
                    # Always fail authentication
                    resp = _session_setup_response(
                        message_id, session_id, b"", STATUS_LOGON_FAILURE
                    )
                    _send_nbss(writer, resp)
                    break
            else:
                # We only implement Negotiate + SessionSetup; other commands
                # could keep an attacker engaged longer but require state we
                # don't carry. Disconnect.
                break
    except (asyncio.IncompleteReadError, ConnectionError):
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


def _send_nbss(writer: asyncio.StreamWriter, smb_pdu: bytes) -> None:
    nbss = bytes([NBSS_SESSION_MESSAGE]) + len(smb_pdu).to_bytes(3, "big")
    writer.write(nbss + smb_pdu)


async def _main() -> None:
    _log("startup", msg=f"SMB server starting as {NODE_NAME}")
    server = await asyncio.start_server(_handle_client, LISTEN_HOST, LISTEN_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        _log("shutdown")
