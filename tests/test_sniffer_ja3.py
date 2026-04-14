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
_parse_certificate = _srv._parse_certificate
_ja3 = _srv._ja3
_ja3s = _srv._ja3s
_ja4 = _srv._ja4
_ja4s = _srv._ja4s
_ja4_version = _srv._ja4_version
_ja4_alpn_tag = _srv._ja4_alpn_tag
_sha256_12 = _srv._sha256_12
_session_resumption_info = _srv._session_resumption_info
_is_grease = _srv._is_grease
_filter_grease = _srv._filter_grease
_tls_version_str = _srv._tls_version_str
_parse_x509_der = _srv._parse_x509_der
_der_read_oid = _srv._der_read_oid


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


# ─── Extension builder helpers for new tests ─────────────────────────────────

def _build_signature_algorithms_extension(sig_algs: list[int]) -> bytes:
    sa_bytes = b"".join(struct.pack("!H", s) for s in sig_algs)
    data = struct.pack("!H", len(sa_bytes)) + sa_bytes
    return _build_extension(0x000D, data)


def _build_supported_versions_extension(versions: list[int]) -> bytes:
    v_bytes = b"".join(struct.pack("!H", v) for v in versions)
    data = bytes([len(v_bytes)]) + v_bytes
    return _build_extension(0x002B, data)


def _build_session_ticket_extension(ticket_data: bytes = b"") -> bytes:
    return _build_extension(0x0023, ticket_data)


def _build_psk_extension() -> bytes:
    return _build_extension(0x0029, b"\x00\x01\x00")


def _build_early_data_extension() -> bytes:
    return _build_extension(0x002A, b"")


def _build_server_hello_with_exts(
    version: int = 0x0303,
    cipher_suite: int = 0x002F,
    extensions_bytes: bytes = b"",
    selected_version: int | None = None,
    alpn: str | None = None,
) -> bytes:
    """Build a ServerHello with optional supported_versions and ALPN extensions."""
    ext_parts = b""
    if selected_version is not None:
        ext_parts += _build_extension(0x002B, struct.pack("!H", selected_version))
    if alpn is not None:
        proto = alpn.encode()
        proto_data = bytes([len(proto)]) + proto
        alpn_data = struct.pack("!H", len(proto_data)) + proto_data
        ext_parts += _build_extension(0x0010, alpn_data)
    if extensions_bytes:
        ext_parts += extensions_bytes
    return _build_server_hello(version=version, cipher_suite=cipher_suite, extensions_bytes=ext_parts)


# ─── ClientHello extended field tests ────────────────────────────────────────

class TestClientHelloExtendedFields:
    def test_signature_algorithms_extracted(self):
        ext = _build_signature_algorithms_extension([0x0401, 0x0501, 0x0601])
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["signature_algorithms"] == [0x0401, 0x0501, 0x0601]

    def test_supported_versions_extracted(self):
        ext = _build_supported_versions_extension([0x0304, 0x0303])
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["supported_versions"] == [0x0304, 0x0303]

    def test_grease_filtered_from_supported_versions(self):
        ext = _build_supported_versions_extension([0x0A0A, 0x0304, 0x0303])
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert 0x0A0A not in result["supported_versions"]
        assert 0x0304 in result["supported_versions"]

    def test_session_ticket_empty_no_resumption(self):
        ext = _build_session_ticket_extension(b"")
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["has_session_ticket_data"] is False

    def test_session_ticket_with_data_resumption(self):
        ext = _build_session_ticket_extension(b"\x01\x02\x03\x04")
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["has_session_ticket_data"] is True

    def test_psk_extension_detected(self):
        ext = _build_psk_extension()
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["has_pre_shared_key"] is True

    def test_early_data_extension_detected(self):
        ext = _build_early_data_extension()
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["has_early_data"] is True

    def test_no_resumption_by_default(self):
        data = _build_client_hello()
        result = _parse_client_hello(data)
        assert result is not None
        assert result["has_session_ticket_data"] is False
        assert result["has_pre_shared_key"] is False
        assert result["has_early_data"] is False

    def test_combined_extensions_all_parsed(self):
        """All new extensions should be parsed alongside existing ones."""
        ext = (
            _build_sni_extension("evil.c2.io")
            + _build_supported_groups_extension([0x001D])
            + _build_signature_algorithms_extension([0x0401])
            + _build_supported_versions_extension([0x0304, 0x0303])
            + _build_alpn_extension(["h2"])
        )
        data = _build_client_hello(extensions_bytes=ext)
        result = _parse_client_hello(data)
        assert result is not None
        assert result["sni"] == "evil.c2.io"
        assert result["supported_groups"] == [0x001D]
        assert result["signature_algorithms"] == [0x0401]
        assert result["supported_versions"] == [0x0304, 0x0303]
        assert result["alpn"] == ["h2"]


# ─── ServerHello extended field tests ────────────────────────────────────────

class TestServerHelloExtendedFields:
    def test_selected_version_extracted(self):
        data = _build_server_hello_with_exts(selected_version=0x0304)
        result = _parse_server_hello(data)
        assert result is not None
        assert result["selected_version"] == 0x0304

    def test_no_selected_version_returns_none(self):
        data = _build_server_hello()
        result = _parse_server_hello(data)
        assert result is not None
        assert result["selected_version"] is None

    def test_alpn_extracted_from_server_hello(self):
        data = _build_server_hello_with_exts(alpn="h2")
        result = _parse_server_hello(data)
        assert result is not None
        assert result["alpn"] == "h2"


# ─── JA4 tests ───────────────────────────────────────────────────────────────

class TestJA4:
    def test_ja4_format_three_sections(self):
        """JA4 must have format: section_a_section_b_section_c"""
        ch = {
            "tls_version": 0x0303,
            "cipher_suites": [0x002F, 0x0035],
            "extensions": [0x000A, 0x000D],
            "supported_groups": [0x001D],
            "ec_point_formats": [0x00],
            "signature_algorithms": [0x0401],
            "supported_versions": [],
            "sni": "test.com",
            "alpn": ["h2"],
        }
        result = _ja4(ch)
        parts = result.split("_")
        assert len(parts) == 3

    def test_ja4_section_a_format(self):
        ch = {
            "tls_version": 0x0303,
            "cipher_suites": [0x002F, 0x0035],
            "extensions": [0x000A, 0x000D, 0x0010],
            "supported_groups": [],
            "ec_point_formats": [],
            "signature_algorithms": [0x0401],
            "supported_versions": [0x0304, 0x0303],
            "sni": "target.local",
            "alpn": ["h2", "http/1.1"],
        }
        result = _ja4(ch)
        section_a = result.split("_")[0]
        # t = TCP, 13 = TLS 1.3 (from supported_versions), d = has SNI
        # 02 = 2 ciphers, 03 = 3 extensions, h2 = ALPN first proto
        assert section_a == "t13d0203h2"

    def test_ja4_no_sni_uses_i(self):
        ch = {
            "tls_version": 0x0303,
            "cipher_suites": [0x002F],
            "extensions": [],
            "supported_groups": [],
            "ec_point_formats": [],
            "signature_algorithms": [],
            "supported_versions": [],
            "sni": "",
            "alpn": [],
        }
        result = _ja4(ch)
        section_a = result.split("_")[0]
        assert section_a[3] == "i"  # no SNI → 'i'

    def test_ja4_no_alpn_uses_00(self):
        ch = {
            "tls_version": 0x0303,
            "cipher_suites": [0x002F],
            "extensions": [],
            "supported_groups": [],
            "ec_point_formats": [],
            "signature_algorithms": [],
            "supported_versions": [],
            "sni": "",
            "alpn": [],
        }
        result = _ja4(ch)
        section_a = result.split("_")[0]
        assert section_a.endswith("00")

    def test_ja4_section_b_is_sha256_12(self):
        ch = {
            "tls_version": 0x0303,
            "cipher_suites": [0x0035, 0x002F],  # unsorted
            "extensions": [],
            "supported_groups": [],
            "ec_point_formats": [],
            "signature_algorithms": [],
            "supported_versions": [],
            "sni": "",
            "alpn": [],
        }
        result = _ja4(ch)
        section_b = result.split("_")[1]
        assert len(section_b) == 12
        # Should be SHA256 of sorted ciphers: "47,53"
        expected = hashlib.sha256(b"47,53").hexdigest()[:12]
        assert section_b == expected

    def test_ja4_section_c_includes_signature_algorithms(self):
        ch = {
            "tls_version": 0x0303,
            "cipher_suites": [0x002F],
            "extensions": [0x000D],  # sig_algs extension type
            "supported_groups": [],
            "ec_point_formats": [],
            "signature_algorithms": [0x0601, 0x0401],
            "supported_versions": [],
            "sni": "",
            "alpn": [],
        }
        result = _ja4(ch)
        section_c = result.split("_")[2]
        assert len(section_c) == 12
        # combined = "13_1025,1537" (sorted ext=13, sorted sig_algs=0x0401=1025, 0x0601=1537)
        expected = hashlib.sha256(b"13_1025,1537").hexdigest()[:12]
        assert section_c == expected

    def test_ja4_same_ciphers_different_order_same_hash(self):
        base = {
            "tls_version": 0x0303,
            "extensions": [],
            "supported_groups": [],
            "ec_point_formats": [],
            "signature_algorithms": [],
            "supported_versions": [],
            "sni": "",
            "alpn": [],
        }
        ch1 = {**base, "cipher_suites": [0x002F, 0x0035]}
        ch2 = {**base, "cipher_suites": [0x0035, 0x002F]}
        assert _ja4(ch1) == _ja4(ch2)

    def test_ja4_different_ciphers_different_hash(self):
        base = {
            "tls_version": 0x0303,
            "extensions": [],
            "supported_groups": [],
            "ec_point_formats": [],
            "signature_algorithms": [],
            "supported_versions": [],
            "sni": "",
            "alpn": [],
        }
        ch1 = {**base, "cipher_suites": [0x002F]}
        ch2 = {**base, "cipher_suites": [0x0035]}
        assert _ja4(ch1) != _ja4(ch2)

    def test_ja4_roundtrip_from_bytes(self):
        """Build a ClientHello from bytes and compute JA4."""
        ext = (
            _build_sni_extension("c2.attacker.net")
            + _build_signature_algorithms_extension([0x0401, 0x0501])
            + _build_supported_versions_extension([0x0304, 0x0303])
            + _build_alpn_extension(["h2"])
        )
        data = _build_client_hello(
            cipher_suites=[0x1301, 0x1302, 0x002F],
            extensions_bytes=ext,
        )
        ch = _parse_client_hello(data)
        assert ch is not None
        result = _ja4(ch)
        parts = result.split("_")
        assert len(parts) == 3
        section_a = parts[0]
        assert section_a.startswith("t13")  # TLS 1.3 via supported_versions
        assert "d" in section_a  # has SNI
        assert section_a.endswith("h2")  # ALPN = h2


# ─── JA4S tests ──────────────────────────────────────────────────────────────

class TestJA4S:
    def test_ja4s_format_two_sections(self):
        sh = {
            "tls_version": 0x0303,
            "cipher_suite": 0x002F,
            "extensions": [0xFF01],
            "selected_version": None,
            "alpn": "",
        }
        result = _ja4s(sh)
        parts = result.split("_")
        assert len(parts) == 2

    def test_ja4s_section_a_format(self):
        sh = {
            "tls_version": 0x0303,
            "cipher_suite": 0x1301,
            "extensions": [0xFF01, 0x002B],
            "selected_version": 0x0304,
            "alpn": "h2",
        }
        result = _ja4s(sh)
        section_a = result.split("_")[0]
        # t = TCP, 13 = TLS 1.3 (selected_version), 02 = 2 extensions, h2 = ALPN
        assert section_a == "t1302h2"

    def test_ja4s_uses_selected_version_when_available(self):
        sh = {
            "tls_version": 0x0303,
            "cipher_suite": 0x1301,
            "extensions": [],
            "selected_version": 0x0304,
            "alpn": "",
        }
        result = _ja4s(sh)
        section_a = result.split("_")[0]
        assert "13" in section_a  # TLS 1.3

    def test_ja4s_falls_back_to_tls_version(self):
        sh = {
            "tls_version": 0x0303,
            "cipher_suite": 0x002F,
            "extensions": [],
            "selected_version": None,
            "alpn": "",
        }
        result = _ja4s(sh)
        section_a = result.split("_")[0]
        assert section_a.startswith("t12")  # TLS 1.2

    def test_ja4s_section_b_is_sha256_12(self):
        sh = {
            "tls_version": 0x0303,
            "cipher_suite": 0x002F,  # 47
            "extensions": [0xFF01],  # 65281
            "selected_version": None,
            "alpn": "",
        }
        result = _ja4s(sh)
        section_b = result.split("_")[1]
        assert len(section_b) == 12
        expected = hashlib.sha256(b"47,65281").hexdigest()[:12]
        assert section_b == expected

    def test_ja4s_roundtrip_from_bytes(self):
        data = _build_server_hello_with_exts(
            cipher_suite=0x1301,
            selected_version=0x0304,
            alpn="h2",
        )
        sh = _parse_server_hello(data)
        assert sh is not None
        result = _ja4s(sh)
        parts = result.split("_")
        assert len(parts) == 2
        assert parts[0].startswith("t13")


# ─── JA4 version detection tests ─────────────────────────────────────────────

class TestJA4Version:
    def test_tls13_from_supported_versions(self):
        ch = {"supported_versions": [0x0304, 0x0303], "tls_version": 0x0303}
        assert _ja4_version(ch) == "13"

    def test_tls12_no_supported_versions(self):
        ch = {"supported_versions": [], "tls_version": 0x0303}
        assert _ja4_version(ch) == "12"

    def test_tls10(self):
        ch = {"supported_versions": [], "tls_version": 0x0301}
        assert _ja4_version(ch) == "10"

    def test_ssl30(self):
        ch = {"supported_versions": [], "tls_version": 0x0300}
        assert _ja4_version(ch) == "s3"

    def test_unknown_version(self):
        ch = {"supported_versions": [], "tls_version": 0xFFFF}
        assert _ja4_version(ch) == "00"


# ─── JA4 ALPN tag tests ──────────────────────────────────────────────────────

class TestJA4AlpnTag:
    def test_h2(self):
        assert _ja4_alpn_tag(["h2"]) == "h2"

    def test_http11(self):
        assert _ja4_alpn_tag(["http/1.1"]) == "h1"

    def test_no_alpn(self):
        assert _ja4_alpn_tag([]) == "00"

    def test_single_char_protocol(self):
        assert _ja4_alpn_tag(["x"]) == "xx"

    def test_string_input(self):
        assert _ja4_alpn_tag("h2") == "h2"

    def test_empty_string(self):
        assert _ja4_alpn_tag("") == "00"


# ─── SHA256-12 tests ─────────────────────────────────────────────────────────

class TestSha256_12:
    def test_returns_12_hex_chars(self):
        result = _sha256_12("test")
        assert len(result) == 12
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic(self):
        assert _sha256_12("hello") == _sha256_12("hello")

    def test_different_input_different_output(self):
        assert _sha256_12("a") != _sha256_12("b")

    def test_matches_hashlib(self):
        expected = hashlib.sha256(b"test_input").hexdigest()[:12]
        assert _sha256_12("test_input") == expected


# ─── Session resumption tests ────────────────────────────────────────────────

class TestSessionResumption:
    def test_no_resumption_by_default(self):
        ch = {
            "has_session_ticket_data": False,
            "has_pre_shared_key": False,
            "has_early_data": False,
            "session_id": b"",
        }
        info = _session_resumption_info(ch)
        assert info["resumption_attempted"] is False
        assert info["mechanisms"] == []

    def test_session_ticket_resumption(self):
        ch = {
            "has_session_ticket_data": True,
            "has_pre_shared_key": False,
            "has_early_data": False,
            "session_id": b"",
        }
        info = _session_resumption_info(ch)
        assert info["resumption_attempted"] is True
        assert "session_ticket" in info["mechanisms"]

    def test_psk_resumption(self):
        ch = {
            "has_session_ticket_data": False,
            "has_pre_shared_key": True,
            "has_early_data": False,
            "session_id": b"",
        }
        info = _session_resumption_info(ch)
        assert info["resumption_attempted"] is True
        assert "psk" in info["mechanisms"]

    def test_early_data_0rtt(self):
        ch = {
            "has_session_ticket_data": False,
            "has_pre_shared_key": False,
            "has_early_data": True,
            "session_id": b"",
        }
        info = _session_resumption_info(ch)
        assert info["resumption_attempted"] is True
        assert "early_data_0rtt" in info["mechanisms"]

    def test_session_id_resumption(self):
        ch = {
            "has_session_ticket_data": False,
            "has_pre_shared_key": False,
            "has_early_data": False,
            "session_id": b"\x01\x02\x03",
        }
        info = _session_resumption_info(ch)
        assert info["resumption_attempted"] is True
        assert "session_id" in info["mechanisms"]

    def test_multiple_mechanisms(self):
        ch = {
            "has_session_ticket_data": True,
            "has_pre_shared_key": True,
            "has_early_data": True,
            "session_id": b"\x01",
        }
        info = _session_resumption_info(ch)
        assert info["resumption_attempted"] is True
        assert len(info["mechanisms"]) == 4

    def test_resumption_from_parsed_client_hello(self):
        ext = _build_session_ticket_extension(b"\xDE\xAD\xBE\xEF")
        data = _build_client_hello(extensions_bytes=ext)
        ch = _parse_client_hello(data)
        assert ch is not None
        info = _session_resumption_info(ch)
        assert info["resumption_attempted"] is True
        assert "session_ticket" in info["mechanisms"]


# ─── Certificate parsing tests ───────────────────────────────────────────────

def _build_der_length(length: int) -> bytes:
    """Encode a DER length."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82]) + struct.pack("!H", length)


def _build_der_sequence(content: bytes) -> bytes:
    return b"\x30" + _build_der_length(len(content)) + content


def _build_der_set(content: bytes) -> bytes:
    return b"\x31" + _build_der_length(len(content)) + content


def _build_der_oid_bytes(oid_str: str) -> bytes:
    """Encode a dotted OID string to DER OID bytes."""
    parts = [int(x) for x in oid_str.split(".")]
    first_byte = parts[0] * 40 + parts[1]
    encoded = bytes([first_byte])
    for val in parts[2:]:
        if val < 0x80:
            encoded += bytes([val])
        else:
            octets = []
            while val > 0:
                octets.append(val & 0x7F)
                val >>= 7
            octets.reverse()
            for i in range(len(octets) - 1):
                octets[i] |= 0x80
            encoded += bytes(octets)
    return b"\x06" + _build_der_length(len(encoded)) + encoded


def _build_der_utf8string(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return b"\x0C" + _build_der_length(len(encoded)) + encoded


def _build_der_utctime(time_str: str) -> bytes:
    encoded = time_str.encode("ascii")
    return b"\x17" + _build_der_length(len(encoded)) + encoded


def _build_rdn(oid: str, value: str) -> bytes:
    """Build a single RDN SET { SEQUENCE { OID, UTF8String } }."""
    attr = _build_der_sequence(_build_der_oid_bytes(oid) + _build_der_utf8string(value))
    return _build_der_set(attr)


def _build_x509_name(cn: str, o: str = "", c: str = "") -> bytes:
    """Build an X.501 Name with optional CN, O, C."""
    rdns = b""
    if c:
        rdns += _build_rdn("2.5.4.6", c)
    if o:
        rdns += _build_rdn("2.5.4.10", o)
    if cn:
        rdns += _build_rdn("2.5.4.3", cn)
    return _build_der_sequence(rdns)


def _build_minimal_tbs_certificate(
    subject_cn: str = "evil.c2.local",
    issuer_cn: str = "Evil CA",
    not_before: str = "230101000000Z",
    not_after: str = "260101000000Z",
    self_signed: bool = False,
) -> bytes:
    """Build a minimal tbsCertificate DER structure."""
    if self_signed:
        issuer_cn = subject_cn

    # version [0] EXPLICIT INTEGER 2 (v3)
    version = b"\xa0\x03\x02\x01\x02"
    # serialNumber INTEGER
    serial = b"\x02\x01\x01"
    # signature algorithm (sha256WithRSAEncryption = 1.2.840.113549.1.1.11)
    sig_alg = _build_der_sequence(_build_der_oid_bytes("1.2.840.113549.1.1.11") + b"\x05\x00")
    # issuer
    issuer = _build_x509_name(issuer_cn)
    # validity
    validity = _build_der_sequence(
        _build_der_utctime(not_before) + _build_der_utctime(not_after)
    )
    # subject
    subject = _build_x509_name(subject_cn)
    # subjectPublicKeyInfo (minimal RSA placeholder)
    spki = _build_der_sequence(
        _build_der_sequence(_build_der_oid_bytes("1.2.840.113549.1.1.1") + b"\x05\x00")
        + b"\x03\x03\x00\x00\x01"
    )

    tbs = version + serial + sig_alg + issuer + validity + subject + spki
    return _build_der_sequence(tbs)


def _build_certificate_der(
    subject_cn: str = "evil.c2.local",
    issuer_cn: str = "Evil CA",
    self_signed: bool = False,
    not_before: str = "230101000000Z",
    not_after: str = "260101000000Z",
) -> bytes:
    """Build a complete X.509 DER certificate (minimal)."""
    tbs = _build_minimal_tbs_certificate(
        subject_cn=subject_cn, issuer_cn=issuer_cn,
        self_signed=self_signed, not_before=not_before, not_after=not_after,
    )
    # signatureAlgorithm
    sig_alg = _build_der_sequence(_build_der_oid_bytes("1.2.840.113549.1.1.11") + b"\x05\x00")
    # signatureValue (BIT STRING, minimal placeholder)
    sig_val = b"\x03\x03\x00\x00\x01"
    return _build_der_sequence(tbs + sig_alg + sig_val)


def _build_tls_certificate_message(cert_der: bytes) -> bytes:
    """Wrap a DER certificate in a TLS Certificate handshake message."""
    # Certificate entry: 3-byte length + cert
    cert_entry = struct.pack("!I", len(cert_der))[1:] + cert_der
    # Certificates list: 3-byte total length + entries
    certs_list = struct.pack("!I", len(cert_entry))[1:] + cert_entry
    # Handshake header: type(1=0x0B) + 3-byte length
    hs = bytes([0x0B]) + struct.pack("!I", len(certs_list))[1:] + certs_list
    # TLS record header
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


class TestCertificateParsing:
    def test_basic_certificate_parsed(self):
        cert_der = _build_certificate_der(subject_cn="pwned.local", issuer_cn="Fake CA")
        tls_msg = _build_tls_certificate_message(cert_der)
        result = _parse_certificate(tls_msg)
        assert result is not None
        assert result["subject_cn"] == "pwned.local"
        assert "Fake CA" in result["issuer_cn"]

    def test_self_signed_detected(self):
        cert_der = _build_certificate_der(subject_cn="selfsigned.evil", self_signed=True)
        tls_msg = _build_tls_certificate_message(cert_der)
        result = _parse_certificate(tls_msg)
        assert result is not None
        assert result["self_signed"] is True
        assert result["subject_cn"] == "selfsigned.evil"

    def test_not_self_signed(self):
        cert_der = _build_certificate_der(subject_cn="legit.com", issuer_cn="DigiCert")
        tls_msg = _build_tls_certificate_message(cert_der)
        result = _parse_certificate(tls_msg)
        assert result is not None
        assert result["self_signed"] is False

    def test_validity_period_extracted(self):
        cert_der = _build_certificate_der(
            not_before="240601120000Z", not_after="250601120000Z"
        )
        tls_msg = _build_tls_certificate_message(cert_der)
        result = _parse_certificate(tls_msg)
        assert result is not None
        assert "240601" in result["not_before"]
        assert "250601" in result["not_after"]

    def test_non_certificate_message_returns_none(self):
        # Build a ClientHello instead
        data = _build_client_hello()
        assert _parse_certificate(data) is None

    def test_empty_cert_list_returns_none(self):
        # Handshake with 0-length certificate list
        hs = bytes([0x0B, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00])
        tls = b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
        assert _parse_certificate(tls) is None

    def test_too_short_returns_none(self):
        assert _parse_certificate(b"") is None
        assert _parse_certificate(b"\x16\x03\x03") is None

    def test_x509_der_direct(self):
        cert_der = _build_certificate_der(subject_cn="direct.test")
        result = _parse_x509_der(cert_der)
        assert result is not None
        assert result["subject_cn"] == "direct.test"


# ─── DER OID tests ───────────────────────────────────────────────────────────

class TestDerOid:
    def test_cn_oid(self):
        raw = _build_der_oid_bytes("2.5.4.3")
        # Skip tag+length
        _, start, length = _srv._der_read_tag_len(raw, 0)
        oid = _der_read_oid(raw, start, length)
        assert oid == "2.5.4.3"

    def test_sha256_rsa_oid(self):
        raw = _build_der_oid_bytes("1.2.840.113549.1.1.11")
        _, start, length = _srv._der_read_tag_len(raw, 0)
        oid = _der_read_oid(raw, start, length)
        assert oid == "1.2.840.113549.1.1.11"
