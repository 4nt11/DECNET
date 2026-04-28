"""NTLMSSP Type 3 (Authenticate) message parser.

Standalone module shared between any honeypot template that wants to
land NTLM credentials in the universal :class:`Credential` table.
Currently consumed by the SMB and RDP-NLA templates.

The parser is intentionally narrow: only :func:`parse_type3` is public,
and it reads a single Type 3 buffer (the bytes starting with the
``NTLMSSP\\0`` signature). Callers handle SPNEGO unwrapping, SMB
SessionSetup framing, RDP/CredSSP TSRequest parsing, etc.

Reference: MS-NLMP §2.2.1.3 (AUTHENTICATE_MESSAGE).

Cred-shape mapping for the universal Credential model:
- ``principal`` = ``"DOMAIN\\username"`` when domain present, else
  bare username. Both decoded UTF-16-LE when NEGOTIATE_UNICODE is set
  in the message flags (it always is in modern clients).
- ``secret_kind`` = ``"ntlmssp_v2"`` when the NtChallengeResponse is
  ≥ 24 bytes (NTLMv2 carries variable-length blob ≥ 16+8 bytes),
  ``"ntlmssp_v1"`` for the legacy 24-byte fixed response.
- ``secret_b64`` = base64 of the entire NtChallengeResponse bytes.
  This is the canonical "hashcat -m 5600" (NTLMv2) or "-m 5500"
  (NTLMv1) input.
"""
from __future__ import annotations

import base64
import struct
from typing import Optional

NTLMSSP_SIG = b"NTLMSSP\x00"
NEGOTIATE_UNICODE = 0x00000001


def find_ntlmssp(buf: bytes) -> int:
    """Return the offset of the NTLMSSP signature in ``buf`` or -1.

    Useful for callers that have a SPNEGO-wrapped or SMB-embedded blob
    and want to skip straight to the inner Type 1/2/3 message without
    walking the outer ASN.1.
    """
    return buf.find(NTLMSSP_SIG)


def _read_field(buf: bytes, off: int) -> tuple[int, int, int]:
    """Read an NTLMSSP field record: (Len, MaxLen, BufferOffset)."""
    if off + 8 > len(buf):
        return 0, 0, 0
    f_len, f_max, f_off = struct.unpack_from("<HHI", buf, off)
    return f_len, f_max, f_off


def _slice(buf: bytes, off: int, length: int) -> bytes:
    end = off + length
    if off < 0 or end > len(buf) or length < 0:
        return b""
    return buf[off:end]


def _decode_str(raw: bytes, unicode: bool) -> str:
    if unicode:
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("ascii", errors="replace")


def parse_type3(blob: bytes) -> Optional[dict]:
    """Parse an NTLMSSP Type 3 (AUTHENTICATE_MESSAGE) buffer.

    Returns a dict with the universal credential SD shape ready to
    spread into a ``_log(...)`` call::

        {
          "username": "alice",            # service-specific identity
          "domain": "ACME",               # domain (may be empty)
          "principal": "ACME\\\\alice",      # hoisted column
          "secret_kind": "ntlmssp_v2",   # or _v1
          "secret_printable": "<hex>",   # NT response in hex
          "secret_b64": "<base64>",      # NT response, lossless
        }

    Returns ``None`` when ``blob`` is malformed or not a Type 3.
    """
    if len(blob) < 32 or not blob.startswith(NTLMSSP_SIG):
        return None
    msg_type = struct.unpack_from("<I", blob, 8)[0]
    if msg_type != 3:
        return None

    # Field record layout (all from MS-NLMP §2.2.1.3):
    #   12 LmChallengeResponseFields
    #   20 NtChallengeResponseFields
    #   28 DomainNameFields
    #   36 UserNameFields
    #   44 WorkstationFields
    #   52 EncryptedRandomSessionKeyFields
    #   60 NegotiateFlags
    nt_len, _, nt_off = _read_field(blob, 20)
    dom_len, _, dom_off = _read_field(blob, 28)
    user_len, _, user_off = _read_field(blob, 36)
    if len(blob) < 64:
        return None
    flags = struct.unpack_from("<I", blob, 60)[0]
    unicode = bool(flags & NEGOTIATE_UNICODE)

    nt_response = _slice(blob, nt_off, nt_len)
    domain = _decode_str(_slice(blob, dom_off, dom_len), unicode)
    username = _decode_str(_slice(blob, user_off, user_len), unicode)

    if not nt_response:
        # No NT response → anonymous bind or malformed; nothing to
        # treat as a credential.
        return None

    # NTLMv2 NTChallengeResponseV2 has a 16-byte HMAC followed by a
    # variable-length blob (≥ 28 bytes total in practice). NTLMv1 is
    # exactly 24 bytes. Use length to discriminate; close enough for
    # cred-classification purposes (the bytes go on hashcat regardless).
    secret_kind = "ntlmssp_v1" if len(nt_response) == 24 else "ntlmssp_v2"

    if domain:
        principal = f"{domain}\\{username}"
    else:
        principal = username or None

    return {
        "username": username,
        "domain": domain,
        "principal": principal,
        "secret_kind": secret_kind,
        "secret_printable": nt_response.hex(),
        "secret_b64": base64.b64encode(nt_response).decode("ascii"),
    }
