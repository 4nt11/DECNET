# SPDX-License-Identifier: AGPL-3.0-or-later
"""NTLMSSP Type 3 parser tests.

Builds Type 3 buffers field-by-field per MS-NLMP §2.2.1.3 and asserts
the parser returns the universal Credential SD shape. Shared
infrastructure for SMB and RDP-NLA cred capture.
"""
from __future__ import annotations

import base64
import importlib.util
import struct
from pathlib import Path

import pytest


def _load_ntlmssp():
    repo = Path(__file__).resolve().parents[2]
    path = repo / "decnet" / "templates" / "_shared" / "ntlmssp.py"
    spec = importlib.util.spec_from_file_location("_ntlmssp_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def ntlmssp():
    return _load_ntlmssp()


def _build_type3(
    *,
    username: str,
    domain: str,
    nt_response: bytes,
    unicode: bool = True,
) -> bytes:
    """Build a syntactically-valid NTLMSSP Type 3 message."""
    if unicode:
        u = username.encode("utf-16-le")
        d = domain.encode("utf-16-le")
        flags = 0x00000001  # NEGOTIATE_UNICODE
    else:
        u = username.encode("ascii")
        d = domain.encode("ascii")
        flags = 0x00000000

    # Layout: 8 sig + 4 type + 6×8 field records + 4 flags = 64 bytes
    # of header, then payload (concat of nt_response, domain, username).
    header_size = 64
    nt_off = header_size
    dom_off = nt_off + len(nt_response)
    user_off = dom_off + len(d)

    hdr = bytearray(header_size)
    hdr[0:8] = b"NTLMSSP\x00"
    struct.pack_into("<I", hdr, 8, 3)  # message type 3
    # LmChallengeResponse (unused — empty)
    struct.pack_into("<HHI", hdr, 12, 0, 0, 0)
    # NtChallengeResponse
    struct.pack_into("<HHI", hdr, 20, len(nt_response), len(nt_response), nt_off)
    # DomainName
    struct.pack_into("<HHI", hdr, 28, len(d), len(d), dom_off)
    # UserName
    struct.pack_into("<HHI", hdr, 36, len(u), len(u), user_off)
    # Workstation (unused)
    struct.pack_into("<HHI", hdr, 44, 0, 0, 0)
    # EncryptedRandomSessionKey (unused)
    struct.pack_into("<HHI", hdr, 52, 0, 0, 0)
    # NegotiateFlags
    struct.pack_into("<I", hdr, 60, flags)

    return bytes(hdr) + nt_response + d + u


def test_parse_type3_ntlmv2(ntlmssp):
    """NTLMv2 NTChallengeResponse is variable-length (>= 28 bytes in
    practice). Parser flags this as secret_kind=ntlmssp_v2."""
    nt_response = b"\xab" * 16 + b"\x01\x01\x00\x00" + b"\x00" * 28  # ~48 bytes
    blob = _build_type3(
        username="alice", domain="ACME", nt_response=nt_response,
    )
    cred = ntlmssp.parse_type3(blob)
    assert cred is not None
    assert cred["username"] == "alice"
    assert cred["domain"] == "ACME"
    assert cred["principal"] == "ACME\\alice"
    assert cred["secret_kind"] == "ntlmssp_v2"
    assert base64.b64decode(cred["secret_b64"]) == nt_response


def test_parse_type3_ntlmv1(ntlmssp):
    """NTLMv1 NTChallengeResponse is exactly 24 bytes."""
    nt_response = b"\xcd" * 24
    blob = _build_type3(
        username="bob", domain="WORKGROUP", nt_response=nt_response,
    )
    cred = ntlmssp.parse_type3(blob)
    assert cred["secret_kind"] == "ntlmssp_v1"
    assert cred["principal"] == "WORKGROUP\\bob"


def test_parse_type3_no_domain(ntlmssp):
    nt_response = b"\xff" * 24
    blob = _build_type3(
        username="lonely", domain="", nt_response=nt_response,
    )
    cred = ntlmssp.parse_type3(blob)
    assert cred["domain"] == ""
    assert cred["principal"] == "lonely"


def test_parse_type3_oem_strings(ntlmssp):
    """Older clients without NEGOTIATE_UNICODE send ASCII strings."""
    nt_response = b"\x11" * 24
    blob = _build_type3(
        username="ascii_user",
        domain="WIN2000",
        nt_response=nt_response,
        unicode=False,
    )
    cred = ntlmssp.parse_type3(blob)
    assert cred["username"] == "ascii_user"
    assert cred["domain"] == "WIN2000"


def test_parse_type3_rejects_non_signature(ntlmssp):
    assert ntlmssp.parse_type3(b"NotNtlmssp") is None
    assert ntlmssp.parse_type3(b"") is None
    # Right magic but wrong message type:
    blob = bytearray(64)
    blob[0:8] = b"NTLMSSP\x00"
    struct.pack_into("<I", blob, 8, 1)  # Type 1, not 3
    assert ntlmssp.parse_type3(bytes(blob)) is None


def test_parse_type3_rejects_anonymous(ntlmssp):
    """Empty NT response (anonymous bind) → no credential to record."""
    blob = _build_type3(username="", domain="", nt_response=b"")
    assert ntlmssp.parse_type3(blob) is None


def test_find_ntlmssp_inside_outer_blob(ntlmssp):
    """SPNEGO-wrapped Type 3 — caller can locate the signature first
    and slice from there. Tests the find_ntlmssp helper."""
    nt_response = b"\xee" * 32
    inner = _build_type3(
        username="x", domain="y", nt_response=nt_response,
    )
    outer = b"\x60\x82\x01\x00" + b"\x00" * 16 + inner + b"\xff" * 8
    off = ntlmssp.find_ntlmssp(outer)
    assert off >= 0
    cred = ntlmssp.parse_type3(outer[off:])
    assert cred["username"] == "x"
