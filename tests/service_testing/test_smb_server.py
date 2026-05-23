# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for decnet/templates/smb/server.py — hand-rolled SMB2 framer.

Drives the asyncio handler with an in-memory StreamReader and a mocked
StreamWriter. Exercises the full Negotiate → SessionSetup(Type1) →
SessionSetup(Type3) flow and asserts that an NTLMSSP Type 3 lands in
the universal credential SD shape.
"""
from __future__ import annotations

import asyncio
import importlib.util
import struct
import sys
from unittest.mock import MagicMock

import pytest

from .conftest import load_real_instance_seed, make_fake_syslog_bridge


# ── Module loader ─────────────────────────────────────────────────────────────


def _load_real_ntlmssp():
    spec = importlib.util.spec_from_file_location(
        "ntlmssp", "decnet/templates/_shared/ntlmssp.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_smb():
    for key in ("smb_server", "syslog_bridge", "instance_seed", "ntlmssp"):
        sys.modules.pop(key, None)
    sys.modules["syslog_bridge"] = make_fake_syslog_bridge()
    sys.modules["instance_seed"] = load_real_instance_seed()
    sys.modules["ntlmssp"] = _load_real_ntlmssp()
    spec = importlib.util.spec_from_file_location(
        "smb_server", "decnet/templates/smb/server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def smb_mod():
    return _load_smb()


def _make_streams():
    """Return (reader, writer, written) — writer.write() collects bytes.

    Must be called from inside a running event loop because
    asyncio.StreamReader's __init__ needs one in Python 3.11.
    """
    reader = asyncio.StreamReader()
    writer = MagicMock()
    written: list[bytes] = []
    writer.write.side_effect = written.append
    writer.get_extra_info.return_value = ("198.51.100.7", 51234)

    async def _wait_closed():
        return None

    writer.wait_closed = _wait_closed
    return reader, writer, written


# ── PDU builders ──────────────────────────────────────────────────────────────


def _nbss(payload: bytes) -> bytes:
    return bytes([0x00]) + len(payload).to_bytes(3, "big") + payload


def _smb2_header(command: int, message_id: int, session_id: int = 0) -> bytes:
    return (
        b"\xfeSMB"
        + struct.pack("<H", 64)
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)
        + struct.pack("<H", command)
        + struct.pack("<H", 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", message_id)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", session_id)
        + b"\x00" * 16
    )


def _negotiate_request() -> bytes:
    # SMB2 NEGOTIATE Request (MS-SMB2 §2.2.3) — minimal, 1 dialect
    body = (
        struct.pack("<H", 36)             # StructureSize
        + struct.pack("<H", 1)            # DialectCount
        + struct.pack("<H", 0)            # SecurityMode
        + struct.pack("<H", 0)            # Reserved
        + struct.pack("<I", 0)            # Capabilities
        + b"\x00" * 16                    # ClientGuid
        + struct.pack("<Q", 0)            # ClientStartTime
        + struct.pack("<H", 0x0210)       # Dialect = SMB 2.1
        + struct.pack("<H", 0)            # padding
    )
    return _smb2_header(0x0000, 0) + body


def _session_setup_request(message_id: int, sec_blob: bytes) -> bytes:
    body = (
        struct.pack("<H", 25)             # StructureSize
        + struct.pack("<B", 0)            # Flags
        + struct.pack("<B", 0)            # SecurityMode
        + struct.pack("<I", 0)            # Capabilities
        + struct.pack("<I", 0)            # Channel
        + struct.pack("<H", 64 + 24)      # SecurityBufferOffset
        + struct.pack("<H", len(sec_blob))
        + struct.pack("<Q", 0)            # PreviousSessionId
    )
    return _smb2_header(0x0001, message_id) + body + sec_blob


def _ntlmssp_type1() -> bytes:
    return b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", 0xE2088297) + b"\x00" * 24


def _ntlmssp_type3(username: str, domain: str, nt_response: bytes) -> bytes:
    """Build a minimal valid NTLMSSP Type 3 with NEGOTIATE_UNICODE."""
    user_b = username.encode("utf-16-le")
    dom_b = domain.encode("utf-16-le")
    workstation = b""
    payload = nt_response + dom_b + user_b + workstation

    # 64-byte header + 8-byte version
    nt_off = 72
    dom_off = nt_off + len(nt_response)
    user_off = dom_off + len(dom_b)
    ws_off = user_off + len(user_b)
    flags = 0x00000001  # NEGOTIATE_UNICODE

    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 3)
        + struct.pack("<HHI", 0, 0, ws_off)              # LmChallengeResponseFields (empty)
        + struct.pack("<HHI", len(nt_response), len(nt_response), nt_off)
        + struct.pack("<HHI", len(dom_b), len(dom_b), dom_off)
        + struct.pack("<HHI", len(user_b), len(user_b), user_off)
        + struct.pack("<HHI", 0, 0, ws_off)              # WorkstationFields (empty)
        + struct.pack("<HHI", 0, 0, ws_off)              # EncryptedRandomSessionKey (empty)
        + struct.pack("<I", flags)
        + b"\x00" * 8                                    # Version
        + payload
    )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _drive(smb_mod, request_bytes: bytes):
    async def _run():
        reader, writer, written = _make_streams()
        reader.feed_data(request_bytes)
        reader.feed_eof()
        await asyncio.wait_for(smb_mod._handle_client(reader, writer), timeout=2.0)
        return writer, written

    return asyncio.run(_run())


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_negotiate_response_is_smb2_dialect_0x0210(smb_mod):
    _, written = _drive(smb_mod, _nbss(_negotiate_request()))
    blob = b"".join(written)
    # Skip NBSS header (4 bytes), then SMB2 header (64), body StructureSize, body[2:4]=DialectRevision
    assert blob[:4] == b"\x00\x00\x00\x83" or blob[0] == 0x00
    smb = blob[4:]
    assert smb.startswith(b"\xfeSMB")
    body = smb[64:]
    dialect = struct.unpack_from("<H", body, 4)[0]
    assert dialect == 0x0210


def test_first_session_setup_returns_more_processing_required(smb_mod):
    pkt1 = _nbss(_negotiate_request())
    pkt2 = _nbss(_session_setup_request(1, _ntlmssp_type1()))
    _, written = _drive(smb_mod, pkt1 + pkt2)
    # second response
    assert len(written) >= 2
    smb = written[1][4:]
    status = struct.unpack_from("<I", smb, 8)[0]
    assert status == 0xC0000016  # STATUS_MORE_PROCESSING_REQUIRED
    # SecurityBuffer should carry an NTLMSSP Type 2
    body = smb[64:]
    sec_off = struct.unpack_from("<H", body, 4)[0]
    sec_len = struct.unpack_from("<H", body, 6)[0]
    sec = smb[sec_off:sec_off + sec_len]
    assert b"NTLMSSP\x00" in sec
    type_byte = sec[sec.index(b"NTLMSSP\x00") + 8]
    assert type_byte == 0x02


def test_type3_credential_lands_in_log():
    mod = _load_smb()
    log_mock = sys.modules["syslog_bridge"]
    nt_response = b"\xaa" * 32  # 32-byte NTLMv2 response
    type3 = _ntlmssp_type3("alice", "ACME", nt_response)
    pkts = (
        _nbss(_negotiate_request())
        + _nbss(_session_setup_request(1, _ntlmssp_type1()))
        + _nbss(_session_setup_request(2, type3))
    )
    _drive(mod, pkts)

    # Find the auth_attempt call
    auth_calls = [
        c for c in log_mock.syslog_line.call_args_list
        if len(c.args) >= 3 and c.args[2] == "auth_attempt"
    ]
    assert auth_calls, f"no auth_attempt logged; got: {log_mock.syslog_line.call_args_list}"
    kwargs = auth_calls[0].kwargs
    assert kwargs["principal"] == "ACME\\alice"
    assert kwargs["secret_kind"] == "ntlmssp_v2"
    assert kwargs["username"] == "alice"
    assert kwargs["domain"] == "ACME"
    assert "secret_b64" in kwargs and kwargs["secret_b64"]


def test_second_session_setup_returns_logon_failure(smb_mod):
    nt_response = b"\xbb" * 32
    type3 = _ntlmssp_type3("bob", "", nt_response)
    pkts = (
        _nbss(_negotiate_request())
        + _nbss(_session_setup_request(1, _ntlmssp_type1()))
        + _nbss(_session_setup_request(2, type3))
    )
    _, written = _drive(smb_mod, pkts)
    smb = written[-1][4:]
    status = struct.unpack_from("<I", smb, 8)[0]
    assert status == 0xC000006D  # STATUS_LOGON_FAILURE


def test_oversized_nbss_length_drops_connection(smb_mod):
    # nb_len = 8 MiB > MAX_NBSS_LEN; framer should bail before allocating
    bad = bytes([0x00]) + (8 * 1024 * 1024).to_bytes(3, "big")
    _, written = _drive(smb_mod, bad)
    assert written == []


def test_smb1_negotiate_drops_connection(smb_mod):
    # 0xff 'SMB' is the SMB1 magic — our framer doesn't speak it
    pdu = b"\xffSMB" + b"\x00" * 60
    _, written = _drive(smb_mod, _nbss(pdu))
    assert written == []


def test_short_pdu_below_64_drops(smb_mod):
    # NBSS length < 64 should be rejected
    bad = bytes([0x00]) + (32).to_bytes(3, "big") + b"\x00" * 32
    _, written = _drive(smb_mod, bad)
    assert written == []
