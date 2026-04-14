"""
Unit tests for the JA3/JA3S parsing logic in templates/sniffer/server.py.

Imports the parser functions directly via sys.path manipulation, with
decnet_logging mocked out (it's a container-side stub at template build time).
"""

from __future__ import annotations

import hashlib
import struct
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ─── Import sniffer module with mocked decnet_logging ─────────────────────────

_SNIFFER_DIR = str(Path(__file__).parent.parent / "templates" / "sniffer")

def _load_sniffer():
    """Load templates/sniffer/server.py with decnet_logging stubbed out."""
    # Stub the decnet_logging module that server.py imports
    _stub = types.ModuleType("decnet_logging")
    _stub.SEVERITY_INFO = 6
    _stub.SEVERITY_WARNING = 4
    _stub.syslog_line = MagicMock(return_value="<134>1 fake")
    _stub.write_syslog_file = MagicMock()
    sys.modules.setdefault("decnet_logging", _stub)

    if _SNIFFER_DIR not in sys.path:
        sys.path.insert(0, _SNIFFER_DIR)

    import importlib
    if "server" in sys.modules:
        return sys.modules["server"]
    import server as _srv
    return _srv

_srv = _load_sniffer()

_parse_client_hello = _srv._parse_client_hello
_parse_server_hello = _srv._parse_server_hello
_ja3 = _srv._ja3
_ja3s = _srv._ja3s
_is_grease = _srv._is_grease
_filter_grease = _srv._filter_grease
_tls_version_str = _srv._tls_version_str


# ─── TLS byte builder helpers ─────────────────────────────────────────────────

def _build_client_hello(
    version: int = 0x0303,
    cipher_suites: list[int] | None = None,
    extensions_bytes: bytes = b"",
) -> bytes:
    """Build a minimal valid TLS ClientHello byte sequence."""
    if cipher_suites is None:
        cipher_suites = [0x002F, 0x0035]  # AES-128-SHA, AES-256-SHA

    random_bytes = b"\xAB" * 32
    session_id = b"\x00"  # no session id
    cs_bytes = b"".join(struct.pack("!H", c) for c in cipher_suites)
    cs_len = struct.pack("!H", len(cs_bytes))
    compression = b"\x01\x00"  # 1 method: null

    if extensions_bytes:
        ext_block = struct.pack("!H", len(extensions_bytes)) + extensions_bytes
    else:
        ext_block = b"\x00\x00"

    body = (
        struct.pack("!H", version)
        + random_bytes
        + session_id
        + cs_len
        + cs_bytes
        + compression
        + ext_block
    )

    hs_header = b"\x01" + struct.pack("!I", len(body))[1:]  # type + 3-byte len
    record_payload = hs_header + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(record_payload)) + record_payload
    return record


def _build_extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _build_sni_extension(hostname: str) -> bytes:
    name_bytes = hostname.encode()
    # server_name: type(1) + len(2) + name
    entry = b"\x00" + struct.pack("!H", len(name_bytes)) + name_bytes
    # server_name_list: len(2) + entries
    lst = struct.pack("!H", len(entry)) + entry
    return _build_extension(0x0000, lst)


def _build_supported_groups_extension(groups: list[int]) -> bytes:
    grp_bytes = b"".join(struct.pack("!H", g) for g in groups)
    data = struct.pack("!H", len(grp_bytes)) + grp_bytes
    return _build_extension(0x000A, data)


def _build_ec_point_formats_extension(formats: list[int]) -> bytes:
    pf = bytes(formats)
    data = bytes([len(pf)]) + pf
    return _build_extension(0x000B, data)


def _build_alpn_extension(protocols: list[str]) -> bytes:
    proto_bytes = b""
    for p in protocols:
        pb = p.encode()
        proto_bytes += bytes([len(pb)]) + pb
    data = struct.pack("!H", len(proto_bytes)) + proto_bytes
    return _build_extension(0x0010, data)


def _build_server_hello(
    version: int = 0x0303,
    cipher_suite: int = 0x002F,
    extensions_bytes: bytes = b"",
) -> bytes:
    random_bytes = b"\xCD" * 32
    session_id = b"\x00"
    compression = b"\x00"

    if extensions_bytes:
        ext_block = struct.pack("!H", len(extensions_bytes)) + extensions_bytes
    else:
        ext_block = b"\x00\x00"

    body = (
        struct.pack("!H", version)
        + random_bytes
        + session_id
        + struct.pack("!H", cipher_suite)
        + compression
        + ext_block
    )

    hs_header = b"\x02" + struct.pack("!I", len(body))[1:]
    record_payload = hs_header + body
    return b"\x16\x03\x01" + struct.pack("!H", len(record_payload)) + record_payload


# ─── GREASE tests ─────────────────────────────────────────────────────────────

class TestGrease:
    def test_known_grease_values_detected(self):
        for v in [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
                  0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
                  0xCACA, 0xDADA, 0xEAEA, 0xFAFA]:
            assert _is_grease(v), f"0x{v:04x} should be GREASE"

    def test_non_grease_values_not_detected(self):
        for v in [0x002F, 0x0035, 0x1301, 0x000A, 0xFFFF]:
            assert not _is_grease(v), f"0x{v:04x} should not be GREASE"

    def test_filter_grease_removes_grease(self):
        values = [0x0A0A, 0x002F, 0x1A1A, 0x0035]
        result = _filter_grease(values)
        assert result == [0x002F, 0x0035]

    def test_filter_grease_preserves_all_non_grease(self):
        values = [0x002F, 0x0035, 0x1301]
        assert _filter_grease(values) == values


# ─── ClientHello parsing tests ────────────────────────────────────────────────

class TestParseClientHello:
    def test_minimal_client_hello_parsed(self):
        data = _build_client_hello()
        result = _parse_client_hello(data)
        assert result is not None
        assert result["tls_version"] == 0x0303
        assert result["cipher_suites"] == [0x002F, 0x0035]
        assert result["extensions"] == []
        assert result["supported_groups"] == []
        assert result["ec_point_formats"] == []
        assert result["sni"] == ""
        assert result["alpn"] == []

    def test_wrong_record_type_returns_none(self):
        data = _build_client_hello()
        bad = b"\x14" + data[1:]  # change record type to ChangeCipherSpec
        assert _parse_client_hello(bad) is None

    def test_wrong_handshake_type_returns_none(self):
        data = _build_client_hello()
        # Byte at offset 5 is the handshake type
        bad = data[:5] + b"\x02" + data[6:]  # ServerHello type
        assert _parse_client_hello(bad) is None

    def test_too_short_returns_none(self):
        assert _parse_client_hello(b"\x16\x03\x01") is None
        assert _parse_client_hello(b"") is None

    def test_non_tls_returns_none(self):
        assert _parse_client_hello(b"GET / HTTP/1.1\r\n") is None

    def test_grease_cipher_suites_filtered(self):
        data = _build_client_hello(cipher_suites=[0x0A0A, 0x002F, 0x1A1A, 0x0035])
        result = _parse_client_hello(data)
        assert result is not None
        assert 0x0A0A not in result["cipher_suites"]
        assert 0x1A1A not in result["cipher_suites"]
        assert result["cipher_suites"] == [0x002F, 0x0035]

    def test_sni_extension_extracted(self):
        ext = _build_sni_extension("example.com")
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["sni"] == "example.com"

    def test_supported_groups_extracted(self):
        ext = _build_supported_groups_extension([0x001D, 0x0017, 0x0018])
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["supported_groups"] == [0x001D, 0x0017, 0x0018]

    def test_grease_in_supported_groups_filtered(self):
        ext = _build_supported_groups_extension([0x0A0A, 0x001D])
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert 0x0A0A not in result["supported_groups"]
        assert 0x001D in result["supported_groups"]

    def test_ec_point_formats_extracted(self):
        ext = _build_ec_point_formats_extension([0x00, 0x01])
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["ec_point_formats"] == [0x00, 0x01]

    def test_alpn_extension_extracted(self):
        ext = _build_alpn_extension(["h2", "http/1.1"])
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["alpn"] == ["h2", "http/1.1"]

    def test_multiple_extensions_extracted(self):
        sni = _build_sni_extension("target.local")
        grps = _build_supported_groups_extension([0x001D])
        combined = sni + grps
        data = _build_client_hello(extensions_bytes=combined)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["sni"] == "target.local"
        assert 0x001D in result["supported_groups"]
        # Extension type IDs recorded (SNI=0, supported_groups=10)
        assert 0x0000 in result["extensions"]
        assert 0x000A in result["extensions"]


# ─── ServerHello parsing tests ────────────────────────────────────────────────

class TestParseServerHello:
    def test_minimal_server_hello_parsed(self):
        data = _build_server_hello()
        result = _parse_server_hello(data)
        assert result is not None
        assert result["tls_version"] == 0x0303
        assert result["cipher_suite"] == 0x002F
        assert result["extensions"] == []

    def test_wrong_record_type_returns_none(self):
        data = _build_server_hello()
        bad = b"\x15" + data[1:]
        assert _parse_server_hello(bad) is None

    def test_wrong_handshake_type_returns_none(self):
        data = _build_server_hello()
        bad = data[:5] + b"\x01" + data[6:]  # ClientHello type
        assert _parse_server_hello(bad) is None

    def test_too_short_returns_none(self):
        assert _parse_server_hello(b"") is None

    def test_server_hello_extension_types_recorded(self):
        # Build a ServerHello with a generic extension (type=0xFF01)
        ext_data = _build_extension(0xFF01, b"\x00")
        data = _build_server_hello(extensions_bytes=ext_data)
        result = _parse_server_hello(data)
        assert result is not None
        assert 0xFF01 in result["extensions"]

    def test_grease_extension_in_server_hello_filtered(self):
        ext_data = _build_extension(0x0A0A, b"\x00")
        data = _build_server_hello(extensions_bytes=ext_data)
        result = _parse_server_hello(data)
        assert result is not None
        assert 0x0A0A not in result["extensions"]


# ─── JA3 hash tests ───────────────────────────────────────────────────────────

class TestJA3:
    def test_ja3_returns_32_char_hex(self):
        data = _build_client_hello()
        ch = _parse_client_hello(data)
        _, ja3_hash = _ja3(ch)
        assert len(ja3_hash) == 32
        assert all(c in "0123456789abcdef" for c in ja3_hash)

    def test_ja3_known_hash(self):
        # Minimal ClientHello: TLS 1.2, ciphers [47, 53], no extensions
        ch = {
            "tls_version": 0x0303,   # 771
            "cipher_suites": [0x002F, 0x0035],  # 47, 53
            "extensions": [],
            "supported_groups": [],
            "ec_point_formats": [],
            "sni": "",
            "alpn": [],
        }
        ja3_str, ja3_hash = _ja3(ch)
        assert ja3_str == "771,47-53,,,"
        expected = hashlib.md5(b"771,47-53,,,").hexdigest()
        assert ja3_hash == expected

    def test_ja3_same_input_same_hash(self):
        data = _build_client_hello()
        ch = _parse_client_hello(data)
        _, h1 = _ja3(ch)
        _, h2 = _ja3(ch)
        assert h1 == h2

    def test_ja3_different_ciphers_different_hash(self):
        ch1 = {"tls_version": 0x0303, "cipher_suites": [47], "extensions": [],
               "supported_groups": [], "ec_point_formats": [], "sni": "", "alpn": []}
        ch2 = {"tls_version": 0x0303, "cipher_suites": [53], "extensions": [],
               "supported_groups": [], "ec_point_formats": [], "sni": "", "alpn": []}
        _, h1 = _ja3(ch1)
        _, h2 = _ja3(ch2)
        assert h1 != h2

    def test_ja3_empty_lists_produce_valid_string(self):
        ch = {"tls_version": 0x0303, "cipher_suites": [], "extensions": [],
              "supported_groups": [], "ec_point_formats": [], "sni": "", "alpn": []}
        ja3_str, ja3_hash = _ja3(ch)
        assert ja3_str == "771,,,,"
        assert len(ja3_hash) == 32


# ─── JA3S hash tests ──────────────────────────────────────────────────────────

class TestJA3S:
    def test_ja3s_returns_32_char_hex(self):
        data = _build_server_hello()
        sh = _parse_server_hello(data)
        _, ja3s_hash = _ja3s(sh)
        assert len(ja3s_hash) == 32
        assert all(c in "0123456789abcdef" for c in ja3s_hash)

    def test_ja3s_known_hash(self):
        sh = {"tls_version": 0x0303, "cipher_suite": 0x002F, "extensions": []}
        ja3s_str, ja3s_hash = _ja3s(sh)
        assert ja3s_str == "771,47,"
        expected = hashlib.md5(b"771,47,").hexdigest()
        assert ja3s_hash == expected

    def test_ja3s_different_cipher_different_hash(self):
        sh1 = {"tls_version": 0x0303, "cipher_suite": 0x002F, "extensions": []}
        sh2 = {"tls_version": 0x0303, "cipher_suite": 0x0035, "extensions": []}
        _, h1 = _ja3s(sh1)
        _, h2 = _ja3s(sh2)
        assert h1 != h2


# ─── TLS version string tests ─────────────────────────────────────────────────

class TestTLSVersionStr:
    def test_tls12(self):
        assert _tls_version_str(0x0303) == "TLS 1.2"

    def test_tls13(self):
        assert _tls_version_str(0x0304) == "TLS 1.3"

    def test_tls11(self):
        assert _tls_version_str(0x0302) == "TLS 1.1"

    def test_tls10(self):
        assert _tls_version_str(0x0301) == "TLS 1.0"

    def test_unknown_version(self):
        result = _tls_version_str(0xABCD)
        assert "0xabcd" in result.lower()


# ─── Full round-trip: parse bytes → JA3/JA3S ──────────────────────────────────

class TestRoundTrip:
    def test_client_hello_bytes_to_ja3(self):
        ciphers = [0x1301, 0x1302, 0x002F]
        sni_ext = _build_sni_extension("attacker.c2.com")
        data = _build_client_hello(cipher_suites=ciphers, extensions_bytes=sni_ext)
        ch = _parse_client_hello(data)
        assert ch is not None
        ja3_str, ja3_hash = _ja3(ch)
        assert "4865-4866-47" in ja3_str  # ciphers: 0x1301=4865, 0x1302=4866, 0x002F=47
        assert len(ja3_hash) == 32
        assert ch["sni"] == "attacker.c2.com"

    def test_server_hello_bytes_to_ja3s(self):
        data = _build_server_hello(cipher_suite=0x1301)
        sh = _parse_server_hello(data)
        assert sh is not None
        ja3s_str, ja3s_hash = _ja3s(sh)
        assert "4865" in ja3s_str  # 0x1301 = 4865
        assert len(ja3s_hash) == 32

    def test_grease_client_hello_filtered_before_hash(self):
        """GREASE ciphers must be stripped before JA3 is computed."""
        ciphers_with_grease = [0x0A0A, 0x002F, 0xFAFA, 0x0035]
        data = _build_client_hello(cipher_suites=ciphers_with_grease)
        ch = _parse_client_hello(data)
        _, ja3_hash = _ja3(ch)

        # Reference: build without GREASE
        ciphers_clean = [0x002F, 0x0035]
        data_clean = _build_client_hello(cipher_suites=ciphers_clean)
        ch_clean = _parse_client_hello(data_clean)
        _, ja3_hash_clean = _ja3(ch_clean)

        assert ja3_hash == ja3_hash_clean
