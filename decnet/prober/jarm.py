"""
JARM TLS fingerprinting — pure stdlib implementation.

JARM sends 10 crafted TLS ClientHello packets to a target, each varying
TLS version, cipher suite order, extensions, and ALPN values. The
ServerHello responses are parsed and hashed to produce a 62-character
fingerprint that identifies the TLS server implementation.

Reference: https://github.com/salesforce/jarm

Only DECNET import is decnet.telemetry for tracing (zero-cost when disabled).
"""

from __future__ import annotations

import hashlib
import socket
import struct
import time
from typing import Any

from decnet.telemetry import traced as _traced

# ─── Constants ────────────────────────────────────────────────────────────────

JARM_EMPTY_HASH = "0" * 62

_INTER_PROBE_DELAY = 0.1  # seconds between probes to avoid IDS triggers

# TLS version bytes
_TLS_1_0 = b"\x03\x01"
_TLS_1_1 = b"\x03\x02"
_TLS_1_2 = b"\x03\x03"
_TLS_1_3 = b"\x03\x03"  # TLS 1.3 uses 0x0303 in record layer

# TLS record types
_CONTENT_HANDSHAKE = 0x16
_HANDSHAKE_CLIENT_HELLO = 0x01
_HANDSHAKE_SERVER_HELLO = 0x02

# Extension types
_EXT_SERVER_NAME = 0x0000
_EXT_EC_POINT_FORMATS = 0x000B
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SESSION_TICKET = 0x0023
_EXT_ENCRYPT_THEN_MAC = 0x0016
_EXT_EXTENDED_MASTER_SECRET = 0x0017
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_PSK_KEY_EXCHANGE_MODES = 0x002D
_EXT_KEY_SHARE = 0x0033
_EXT_ALPN = 0x0010
_EXT_PADDING = 0x0015

# ─── Cipher suite lists per JARM spec ────────────────────────────────────────

# Forward cipher order (standard)
_CIPHERS_FORWARD = [
    0x0016, 0x0033, 0x0067, 0xC09E, 0xC0A2, 0x009E, 0x0039, 0x006B,
    0xC09F, 0xC0A3, 0x009F, 0x0045, 0x00BE, 0x0088, 0x00C4, 0x009A,
    0xC008, 0xC009, 0xC023, 0xC0AC, 0xC0AE, 0xC02B, 0xC00A, 0xC024,
    0xC0AD, 0xC0AF, 0xC02C, 0xC072, 0xC073, 0xCCA8, 0x1301, 0x1302,
    0x1303, 0xC013, 0xC014, 0xC02F, 0x009C, 0xC02E, 0x002F, 0x0035,
    0x000A, 0x0005, 0x0004,
]

# Reverse cipher order
_CIPHERS_REVERSE = list(reversed(_CIPHERS_FORWARD))

# TLS 1.3-only ciphers
_CIPHERS_TLS13 = [0x1301, 0x1302, 0x1303]

# Middle-out cipher order (interleaved from center)
def _middle_out(lst: list[int]) -> list[int]:
    result: list[int] = []
    mid = len(lst) // 2
    for i in range(mid + 1):
        if mid + i < len(lst):
            result.append(lst[mid + i])
        if mid - i >= 0 and mid - i != mid + i:
            result.append(lst[mid - i])
    return result

_CIPHERS_MIDDLE_OUT = _middle_out(_CIPHERS_FORWARD)

# Rare/uncommon extensions cipher list
_CIPHERS_RARE = [
    0x0016, 0x0033, 0xC011, 0xC012, 0x0067, 0xC09E, 0xC0A2, 0x009E,
    0x0039, 0x006B, 0xC09F, 0xC0A3, 0x009F, 0x0045, 0x00BE, 0x0088,
    0x00C4, 0x009A, 0xC008, 0xC009, 0xC023, 0xC0AC, 0xC0AE, 0xC02B,
    0xC00A, 0xC024, 0xC0AD, 0xC0AF, 0xC02C, 0xC072, 0xC073, 0xCCA8,
    0x1301, 0x1302, 0x1303, 0xC013, 0xC014, 0xC02F, 0x009C, 0xC02E,
    0x002F, 0x0035, 0x000A, 0x0005, 0x0004,
]


# ─── Probe definitions ────────────────────────────────────────────────────────

# Each probe: (tls_version, cipher_list, tls13_support, alpn, extensions_style)
#   tls_version:      record-layer version bytes
#   cipher_list:      which cipher suite ordering to use
#   tls13_support:    whether to include TLS 1.3 extensions (supported_versions, key_share, psk)
#   alpn:             ALPN protocol string or None
#   extensions_style: "standard", "rare", or "no_extensions"

_PROBE_CONFIGS: list[dict[str, Any]] = [
    # 0: TLS 1.2 forward
    {"version": _TLS_1_2, "ciphers": _CIPHERS_FORWARD, "tls13": False, "alpn": None, "style": "standard"},
    # 1: TLS 1.2 reverse
    {"version": _TLS_1_2, "ciphers": _CIPHERS_REVERSE, "tls13": False, "alpn": None, "style": "standard"},
    # 2: TLS 1.1 forward
    {"version": _TLS_1_1, "ciphers": _CIPHERS_FORWARD, "tls13": False, "alpn": None, "style": "standard"},
    # 3: TLS 1.3 forward
    {"version": _TLS_1_2, "ciphers": _CIPHERS_FORWARD, "tls13": True, "alpn": "h2", "style": "standard"},
    # 4: TLS 1.3 reverse
    {"version": _TLS_1_2, "ciphers": _CIPHERS_REVERSE, "tls13": True, "alpn": "h2", "style": "standard"},
    # 5: TLS 1.3 invalid (advertise 1.3 support but no key_share)
    {"version": _TLS_1_2, "ciphers": _CIPHERS_FORWARD, "tls13": "no_key_share", "alpn": None, "style": "standard"},
    # 6: TLS 1.3 middle-out
    {"version": _TLS_1_2, "ciphers": _CIPHERS_MIDDLE_OUT, "tls13": True, "alpn": None, "style": "standard"},
    # 7: TLS 1.0 forward
    {"version": _TLS_1_0, "ciphers": _CIPHERS_FORWARD, "tls13": False, "alpn": None, "style": "standard"},
    # 8: TLS 1.2 middle-out
    {"version": _TLS_1_2, "ciphers": _CIPHERS_MIDDLE_OUT, "tls13": False, "alpn": None, "style": "standard"},
    # 9: TLS 1.2 with rare extensions
    {"version": _TLS_1_2, "ciphers": _CIPHERS_RARE, "tls13": False, "alpn": "http/1.1", "style": "rare"},
]


# ─── Extension builders ──────────────────────────────────────────────────────

def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _ext_sni(host: str) -> bytes:
    host_bytes = host.encode("ascii")
    # ServerNameList: length(2) + ServerName: type(1) + length(2) + name
    sni_data = struct.pack("!HBH", len(host_bytes) + 3, 0, len(host_bytes)) + host_bytes
    return _ext(_EXT_SERVER_NAME, sni_data)


def _ext_supported_groups() -> bytes:
    groups = [0x0017, 0x0018, 0x0019, 0x001D, 0x0100, 0x0101]  # secp256r1, secp384r1, secp521r1, x25519, ffdhe2048, ffdhe3072
    data = struct.pack("!H", len(groups) * 2) + b"".join(struct.pack("!H", g) for g in groups)
    return _ext(_EXT_SUPPORTED_GROUPS, data)


def _ext_ec_point_formats() -> bytes:
    formats = b"\x00"  # uncompressed only
    return _ext(_EXT_EC_POINT_FORMATS, struct.pack("B", len(formats)) + formats)


def _ext_signature_algorithms() -> bytes:
    algos = [
        0x0401, 0x0501, 0x0601,  # RSA PKCS1 SHA256/384/512
        0x0201,                    # RSA PKCS1 SHA1
        0x0403, 0x0503, 0x0603,  # ECDSA SHA256/384/512
        0x0203,                    # ECDSA SHA1
        0x0804, 0x0805, 0x0806,  # RSA-PSS SHA256/384/512
    ]
    data = struct.pack("!H", len(algos) * 2) + b"".join(struct.pack("!H", a) for a in algos)
    return _ext(_EXT_SIGNATURE_ALGORITHMS, data)


def _ext_supported_versions_13() -> bytes:
    versions = [0x0304, 0x0303]  # TLS 1.3, 1.2
    data = struct.pack("B", len(versions) * 2) + b"".join(struct.pack("!H", v) for v in versions)
    return _ext(_EXT_SUPPORTED_VERSIONS, data)


def _ext_psk_key_exchange_modes() -> bytes:
    return _ext(_EXT_PSK_KEY_EXCHANGE_MODES, b"\x01\x01")  # psk_dhe_ke


def _ext_key_share() -> bytes:
    # x25519 key share with 32 random-looking bytes
    key_data = b"\x00" * 32
    entry = struct.pack("!HH", 0x001D, 32) + key_data  # x25519 group
    data = struct.pack("!H", len(entry)) + entry
    return _ext(_EXT_KEY_SHARE, data)


def _ext_alpn(protocol: str) -> bytes:
    proto_bytes = protocol.encode("ascii")
    proto_entry = struct.pack("B", len(proto_bytes)) + proto_bytes
    data = struct.pack("!H", len(proto_entry)) + proto_entry
    return _ext(_EXT_ALPN, data)


def _ext_session_ticket() -> bytes:
    return _ext(_EXT_SESSION_TICKET, b"")


def _ext_encrypt_then_mac() -> bytes:
    return _ext(_EXT_ENCRYPT_THEN_MAC, b"")


def _ext_extended_master_secret() -> bytes:
    return _ext(_EXT_EXTENDED_MASTER_SECRET, b"")


def _ext_padding(target_length: int, current_length: int) -> bytes:
    pad_needed = target_length - current_length - 4  # 4 bytes for ext type + length
    if pad_needed < 0:
        return b""
    return _ext(_EXT_PADDING, b"\x00" * pad_needed)


# ─── ClientHello builder ─────────────────────────────────────────────────────

def _build_client_hello(probe_index: int, host: str = "localhost") -> bytes:
    """
    Construct one of 10 JARM-specified ClientHello packets.

    Args:
        probe_index: 0-9, selects the probe configuration
        host: target hostname for SNI extension

    Returns:
        Complete TLS record bytes ready to send on the wire.
    """
    cfg = _PROBE_CONFIGS[probe_index]
    version: bytes = cfg["version"]
    ciphers: list[int] = cfg["ciphers"]
    tls13 = cfg["tls13"]
    alpn: str | None = cfg["alpn"]

    # Random (32 bytes)
    random_bytes = b"\x00" * 32

    # Session ID (32 bytes, all zeros)
    session_id = b"\x00" * 32

    # Cipher suites
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    cipher_data = struct.pack("!H", len(cipher_bytes)) + cipher_bytes

    # Compression methods (null only)
    compression = b"\x01\x00"

    # Extensions
    extensions = b""
    extensions += _ext_sni(host)
    extensions += _ext_supported_groups()
    extensions += _ext_ec_point_formats()
    extensions += _ext_session_ticket()
    extensions += _ext_encrypt_then_mac()
    extensions += _ext_extended_master_secret()
    extensions += _ext_signature_algorithms()

    if tls13 == True:  # noqa: E712
        extensions += _ext_supported_versions_13()
        extensions += _ext_psk_key_exchange_modes()
        extensions += _ext_key_share()
    elif tls13 == "no_key_share":
        extensions += _ext_supported_versions_13()
        extensions += _ext_psk_key_exchange_modes()
        # Intentionally omit key_share

    if alpn:
        extensions += _ext_alpn(alpn)

    ext_data = struct.pack("!H", len(extensions)) + extensions

    # ClientHello body
    body = (
        version              # client_version (2)
        + random_bytes       # random (32)
        + struct.pack("B", len(session_id)) + session_id  # session_id
        + cipher_data        # cipher_suites
        + compression        # compression_methods
        + ext_data           # extensions
    )

    # Handshake header: type(1) + length(3)
    handshake = struct.pack("B", _HANDSHAKE_CLIENT_HELLO) + struct.pack("!I", len(body))[1:] + body

    # TLS record header: type(1) + version(2) + length(2)
    record = struct.pack("B", _CONTENT_HANDSHAKE) + _TLS_1_0 + struct.pack("!H", len(handshake)) + handshake

    return record


# ─── ServerHello parser ──────────────────────────────────────────────────────

def _parse_server_hello(data: bytes) -> str:
    """
    Extract cipher suite and TLS version from a ServerHello response.

    Returns a pipe-delimited string "cipher|version|extensions" that forms
    one component of the JARM hash, or "|||" on parse failure.
    """
    try:
        if len(data) < 6:
            return "|||"

        # TLS record header
        if data[0] != _CONTENT_HANDSHAKE:
            return "|||"

        struct.unpack_from("!H", data, 1)[0]  # record_version (unused)
        record_len = struct.unpack_from("!H", data, 3)[0]
        hs = data[5: 5 + record_len]

        if len(hs) < 4:
            return "|||"

        # Handshake header
        if hs[0] != _HANDSHAKE_SERVER_HELLO:
            return "|||"

        hs_len = struct.unpack_from("!I", b"\x00" + hs[1:4])[0]
        body = hs[4: 4 + hs_len]

        if len(body) < 34:
            return "|||"

        pos = 0
        # Server version
        server_version = struct.unpack_from("!H", body, pos)[0]
        pos += 2

        # Random (32 bytes)
        pos += 32

        # Session ID
        if pos >= len(body):
            return "|||"
        sid_len = body[pos]
        pos += 1 + sid_len

        # Cipher suite
        if pos + 2 > len(body):
            return "|||"
        cipher = struct.unpack_from("!H", body, pos)[0]
        pos += 2

        # Compression method
        if pos >= len(body):
            return "|||"
        pos += 1

        # Parse extensions for supported_versions (to detect actual TLS 1.3)
        actual_version = server_version
        extensions_str = ""
        if pos + 2 <= len(body):
            ext_total = struct.unpack_from("!H", body, pos)[0]
            pos += 2
            ext_end = pos + ext_total
            ext_types: list[str] = []
            while pos + 4 <= ext_end and pos + 4 <= len(body):
                ext_type = struct.unpack_from("!H", body, pos)[0]
                ext_len = struct.unpack_from("!H", body, pos + 2)[0]
                ext_types.append(f"{ext_type:04x}")

                if ext_type == _EXT_SUPPORTED_VERSIONS and ext_len >= 2:
                    actual_version = struct.unpack_from("!H", body, pos + 4)[0]

                pos += 4 + ext_len
            extensions_str = "-".join(ext_types)

        version_str = _version_to_str(actual_version)
        cipher_str = f"{cipher:04x}"

        return f"{cipher_str}|{version_str}|{extensions_str}"

    except Exception:
        return "|||"


def _version_to_str(version: int) -> str:
    return {
        0x0304: "tls13",
        0x0303: "tls12",
        0x0302: "tls11",
        0x0301: "tls10",
        0x0300: "ssl30",
    }.get(version, f"{version:04x}")


# ─── Probe sender ────────────────────────────────────────────────────────────

@_traced("prober.jarm_send_probe")
def _send_probe(host: str, port: int, hello: bytes, timeout: float = 5.0) -> bytes | None:
    """
    Open a TCP connection, send the ClientHello, and read the ServerHello.

    Returns raw response bytes or None on any failure.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            sock.sendall(hello)
            sock.settimeout(timeout)
            response = b""
            while True:
                chunk = sock.recv(1484)
                if not chunk:
                    break
                response += chunk
                # We only need the first TLS record (ServerHello)
                if len(response) >= 5:
                    record_len = struct.unpack_from("!H", response, 3)[0]
                    if len(response) >= 5 + record_len:
                        break
            return response if response else None
        finally:
            sock.close()
    except (OSError, socket.error, socket.timeout):
        return None


# ─── JARM hash computation ───────────────────────────────────────────────────

def _compute_jarm(responses: list[str]) -> str:
    """
    Compute the final 62-character JARM hash from 10 probe response strings.

    The first 30 characters are the raw cipher/version concatenation.
    The remaining 32 characters are a truncated SHA256 of the extensions.
    """
    if all(r == "|||" for r in responses):
        return JARM_EMPTY_HASH

    # Build the fuzzy hash
    raw_parts: list[str] = []
    ext_parts: list[str] = []

    for r in responses:
        parts = r.split("|")
        if len(parts) >= 3 and parts[0] != "":
            cipher = parts[0]
            version = parts[1]
            extensions = parts[2] if len(parts) > 2 else ""

            # Map version to single char
            ver_char = {
                "tls13": "d", "tls12": "c", "tls11": "b",
                "tls10": "a", "ssl30": "0",
            }.get(version, "0")

            raw_parts.append(f"{cipher}{ver_char}")
            ext_parts.append(extensions)
        else:
            raw_parts.append("000")
            ext_parts.append("")

    # First 30 chars: cipher(4) + version(1) = 5 chars * 10 probes = 50... no
    # JARM spec: first part is c|v per probe joined, then SHA256 of extensions
    # Actual format: each response contributes 3 chars (cipher_first2 + ver_char)
    # to the first 30, then all extensions hashed for the remaining 32.

    fuzzy_raw = ""
    for r in responses:
        parts = r.split("|")
        if len(parts) >= 3 and parts[0] != "":
            cipher = parts[0]  # 4-char hex
            version = parts[1]
            ver_char = {
                "tls13": "d", "tls12": "c", "tls11": "b",
                "tls10": "a", "ssl30": "0",
            }.get(version, "0")
            fuzzy_raw += f"{cipher[0:2]}{ver_char}"
        else:
            fuzzy_raw += "000"

    # fuzzy_raw is 30 chars (3 * 10)
    ext_str = ",".join(ext_parts)
    ext_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:32]

    return fuzzy_raw + ext_hash


# ─── Public API ──────────────────────────────────────────────────────────────

@_traced("prober.jarm_hash")
def jarm_hash(host: str, port: int, timeout: float = 5.0) -> str:
    """
    Compute the JARM fingerprint for a TLS server.

    Sends 10 crafted ClientHello packets and hashes the responses.

    Args:
        host: target IP or hostname
        port: target port
        timeout: per-probe TCP timeout in seconds

    Returns:
        62-character JARM hash string, or all-zeros on total failure.
    """
    responses: list[str] = []

    for i in range(10):
        hello = _build_client_hello(i, host=host)
        raw = _send_probe(host, port, hello, timeout=timeout)
        if raw is not None:
            parsed = _parse_server_hello(raw)
            responses.append(parsed)
        else:
            responses.append("|||")

        if i < 9:
            time.sleep(_INTER_PROBE_DELAY)

    return _compute_jarm(responses)
