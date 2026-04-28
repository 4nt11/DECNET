"""
Tests for the fleet-wide sniffer worker and fingerprinting engine.

Tests the IP-to-decky mapping, packet callback routing, syslog output
format, dedup logic, and worker fault isolation.
"""

import struct
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from decnet.sniffer.fingerprint import (
    SnifferEngine,
    _ja3,
    _ja4,
    _ja4_alpn_tag,
    _ja4_version,
    _ja4s,
    _ja3s,
    _parse_client_hello,
    _parse_server_hello,
    _parse_ssh_banner,
    _session_resumption_info,
    _tls_version_str,
)
from decnet.sniffer.syslog import syslog_line, write_event
from decnet.sniffer.worker import _load_ip_to_decky


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _build_tls_client_hello(
    tls_version: int = 0x0303,
    cipher_suites: list[int] | None = None,
    sni: str = "example.com",
) -> bytes:
    """Build a minimal TLS ClientHello payload for testing."""
    if cipher_suites is None:
        cipher_suites = [0x1301, 0x1302, 0x1303]

    body = b""
    body += struct.pack("!H", tls_version)  # ClientHello version
    body += b"\x00" * 32  # Random
    body += b"\x00"  # Session ID length = 0

    # Cipher suites
    cs_data = b"".join(struct.pack("!H", cs) for cs in cipher_suites)
    body += struct.pack("!H", len(cs_data)) + cs_data

    # Compression methods
    body += b"\x01\x00"  # 1 method, null

    # Extensions
    ext_data = b""
    if sni:
        sni_bytes = sni.encode("ascii")
        sni_ext = struct.pack("!HBH", len(sni_bytes) + 3, 0, len(sni_bytes)) + sni_bytes
        ext_data += struct.pack("!HH", 0x0000, len(sni_ext)) + sni_ext

    body += struct.pack("!H", len(ext_data)) + ext_data

    # Handshake header
    hs = struct.pack("!B", 0x01) + struct.pack("!I", len(body))[1:]  # type + 3-byte length
    hs_with_body = hs + body

    # TLS record header
    record = struct.pack("!BHH", 0x16, 0x0301, len(hs_with_body)) + hs_with_body
    return record


def _build_tls_server_hello(
    tls_version: int = 0x0303,
    cipher_suite: int = 0x1301,
) -> bytes:
    """Build a minimal TLS ServerHello payload for testing."""
    body = b""
    body += struct.pack("!H", tls_version)
    body += b"\x00" * 32  # Random
    body += b"\x00"  # Session ID length = 0
    body += struct.pack("!H", cipher_suite)
    body += b"\x00"  # Compression method

    # No extensions
    body += struct.pack("!H", 0)

    hs = struct.pack("!B", 0x02) + struct.pack("!I", len(body))[1:]
    hs_with_body = hs + body

    record = struct.pack("!BHH", 0x16, 0x0301, len(hs_with_body)) + hs_with_body
    return record


# ─── TLS parser tests ───────────────────────────────────────────────────────

class TestTlsParsers:
    def test_parse_client_hello_valid(self):
        data = _build_tls_client_hello()
        result = _parse_client_hello(data)
        assert result is not None
        assert result["tls_version"] == 0x0303
        assert result["cipher_suites"] == [0x1301, 0x1302, 0x1303]
        assert result["sni"] == "example.com"

    def test_parse_client_hello_no_sni(self):
        data = _build_tls_client_hello(sni="")
        result = _parse_client_hello(data)
        assert result is not None
        assert result["sni"] == ""

    def test_parse_client_hello_invalid_data(self):
        assert _parse_client_hello(b"\x00\x01") is None
        assert _parse_client_hello(b"") is None
        assert _parse_client_hello(b"\x16\x03\x01\x00\x00") is None

    def test_parse_server_hello_valid(self):
        data = _build_tls_server_hello()
        result = _parse_server_hello(data)
        assert result is not None
        assert result["tls_version"] == 0x0303
        assert result["cipher_suite"] == 0x1301

    def test_parse_server_hello_invalid(self):
        assert _parse_server_hello(b"garbage") is None


# ─── SSH banner parser tests ────────────────────────────────────────────────

class TestSshBannerParser:
    def test_openssh_banner_crlf(self):
        data = b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\nkex-init..."
        assert _parse_ssh_banner(data) == "SSH-2.0-OpenSSH_9.2p1 Debian-2"

    def test_banner_lf_only(self):
        data = b"SSH-2.0-libssh2_1.10.0\n"
        assert _parse_ssh_banner(data) == "SSH-2.0-libssh2_1.10.0"

    def test_non_ssh_payload(self):
        assert _parse_ssh_banner(b"GET / HTTP/1.1\r\n") is None
        assert _parse_ssh_banner(b"") is None
        assert _parse_ssh_banner(b"\x16\x03\x01\x00") is None

    def test_missing_terminator(self):
        # No CR/LF within the 255-byte RFC window → not a complete banner yet.
        assert _parse_ssh_banner(b"SSH-2.0-OpenSSH_9.2p1" + b" " * 300) is None

    def test_banner_too_short(self):
        assert _parse_ssh_banner(b"SSH-\r\n") is None

    def test_non_ascii_rejected(self):
        assert _parse_ssh_banner(b"SSH-2.0-\xff\xfe\r\n") is None


# ─── Fingerprint computation tests ──────────────────────────────────────────

class TestFingerprints:
    def test_ja3_deterministic(self):
        data = _build_tls_client_hello()
        ch = _parse_client_hello(data)
        ja3_str1, hash1 = _ja3(ch)
        ja3_str2, hash2 = _ja3(ch)
        assert hash1 == hash2
        assert len(hash1) == 32  # MD5 hex

    def test_ja4_format(self):
        data = _build_tls_client_hello()
        ch = _parse_client_hello(data)
        ja4 = _ja4(ch)
        parts = ja4.split("_")
        assert len(parts) == 3
        assert parts[0].startswith("t")  # TCP

    def test_ja3s_deterministic(self):
        data = _build_tls_server_hello()
        sh = _parse_server_hello(data)
        _, hash1 = _ja3s(sh)
        _, hash2 = _ja3s(sh)
        assert hash1 == hash2

    def test_ja4s_format(self):
        data = _build_tls_server_hello()
        sh = _parse_server_hello(data)
        ja4s = _ja4s(sh)
        parts = ja4s.split("_")
        assert len(parts) == 2
        assert parts[0].startswith("t")

    def test_tls_version_str(self):
        assert _tls_version_str(0x0303) == "TLS 1.2"
        assert _tls_version_str(0x0304) == "TLS 1.3"
        assert "0x" in _tls_version_str(0x9999)

    def test_ja4_version_with_supported_versions(self):
        ch = {"tls_version": 0x0303, "supported_versions": [0x0303, 0x0304]}
        assert _ja4_version(ch) == "13"

    def test_ja4_alpn_tag(self):
        assert _ja4_alpn_tag([]) == "00"
        assert _ja4_alpn_tag(["h2"]) == "h2"
        assert _ja4_alpn_tag(["http/1.1"]) == "h1"

    def test_session_resumption_info(self):
        ch = {"has_session_ticket_data": True, "has_pre_shared_key": False,
              "has_early_data": False, "session_id": b""}
        info = _session_resumption_info(ch)
        assert info["resumption_attempted"] is True
        assert "session_ticket" in info["mechanisms"]


# ─── Syslog format tests ────────────────────────────────────────────────────

class TestSyslog:
    def test_syslog_line_format(self):
        line = syslog_line("sniffer", "decky-01", "tls_client_hello", src_ip="10.0.0.1")
        assert "<134>" in line  # PRI for local0 + INFO
        assert "decky-01" in line
        assert "sniffer" in line
        assert "tls_client_hello" in line
        assert 'src_ip="10.0.0.1"' in line

    def test_write_event_creates_files(self, tmp_path):
        log_path = tmp_path / "test.log"
        json_path = tmp_path / "test.json"
        line = syslog_line("sniffer", "decky-01", "tls_client_hello", src_ip="10.0.0.1")
        write_event(line, log_path, json_path)
        assert log_path.exists()
        assert json_path.exists()
        assert "decky-01" in log_path.read_text()


# ─── SnifferEngine tests ────────────────────────────────────────────────────

class TestSnifferEngine:
    def test_resolve_decky_by_dst(self):
        engine = SnifferEngine(
            ip_to_decky={"192.168.1.10": "decky-01"},
            write_fn=lambda _: None,
        )
        assert engine._resolve_decky("10.0.0.1", "192.168.1.10") == "decky-01"

    def test_resolve_decky_by_src(self):
        engine = SnifferEngine(
            ip_to_decky={"192.168.1.10": "decky-01"},
            write_fn=lambda _: None,
        )
        assert engine._resolve_decky("192.168.1.10", "10.0.0.1") == "decky-01"

    def test_resolve_decky_unknown(self):
        engine = SnifferEngine(
            ip_to_decky={"192.168.1.10": "decky-01"},
            write_fn=lambda _: None,
        )
        assert engine._resolve_decky("10.0.0.1", "10.0.0.2") is None

    def test_update_ip_map(self):
        engine = SnifferEngine(
            ip_to_decky={"192.168.1.10": "decky-01"},
            write_fn=lambda _: None,
        )
        engine.update_ip_map({"192.168.1.20": "decky-02"})
        assert engine._resolve_decky("10.0.0.1", "192.168.1.20") == "decky-02"
        assert engine._resolve_decky("10.0.0.1", "192.168.1.10") is None

    def test_dedup_suppresses_identical_events(self):
        written: list[str] = []
        engine = SnifferEngine(
            ip_to_decky={},
            write_fn=written.append,
            dedup_ttl=300.0,
        )
        fields = {"src_ip": "10.0.0.1", "ja3": "abc", "ja4": "def"}
        engine._log("decky-01", "tls_client_hello", **fields)
        engine._log("decky-01", "tls_client_hello", **fields)
        assert len(written) == 1

    def test_dedup_allows_different_fingerprints(self):
        written: list[str] = []
        engine = SnifferEngine(
            ip_to_decky={},
            write_fn=written.append,
            dedup_ttl=300.0,
        )
        engine._log("decky-01", "tls_client_hello", src_ip="10.0.0.1", ja3="abc", ja4="def")
        engine._log("decky-01", "tls_client_hello", src_ip="10.0.0.1", ja3="xyz", ja4="uvw")
        assert len(written) == 2

    def test_dedup_disabled_when_ttl_zero(self):
        written: list[str] = []
        engine = SnifferEngine(
            ip_to_decky={},
            write_fn=written.append,
            dedup_ttl=0,
        )
        fields = {"src_ip": "10.0.0.1", "ja3": "abc", "ja4": "def"}
        engine._log("decky-01", "tls_client_hello", **fields)
        engine._log("decky-01", "tls_client_hello", **fields)
        assert len(written) == 2


# ─── Worker IP map loading ──────────────────────────────────────────────────

class TestWorkerIpMap:
    def test_load_ip_to_decky_no_state(self):
        with patch("decnet.config.load_state", return_value=None):
            result = _load_ip_to_decky()
            assert result == {}
