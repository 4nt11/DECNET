"""
Unit tests for the JARM fingerprinting module.

Tests cover ClientHello construction, ServerHello parsing, hash computation,
and end-to-end jarm_hash() with mocked sockets.
"""

from __future__ import annotations

import hashlib
import struct
from unittest.mock import MagicMock, patch

import pytest

from decnet.prober.jarm import (
    JARM_EMPTY_HASH,
    _build_client_hello,
    _compute_jarm,
    _middle_out,
    _parse_server_hello,
    _send_probe,
    _version_to_str,
    jarm_hash,
)


# ─── _build_client_hello ─────────────────────────────────────────────────────

class TestBuildClientHello:

    @pytest.mark.parametrize("probe_index", range(10))
    def test_produces_valid_tls_record(self, probe_index: int):
        data = _build_client_hello(probe_index, host="example.com")
        assert isinstance(data, bytes)
        assert len(data) > 5
        # TLS record header: content_type = 0x16 (Handshake)
        assert data[0] == 0x16

    @pytest.mark.parametrize("probe_index", range(10))
    def test_handshake_type_is_client_hello(self, probe_index: int):
        data = _build_client_hello(probe_index, host="example.com")
        # Byte 5 is the handshake type (after 5-byte record header)
        assert data[5] == 0x01  # ClientHello

    @pytest.mark.parametrize("probe_index", range(10))
    def test_record_length_matches(self, probe_index: int):
        data = _build_client_hello(probe_index, host="example.com")
        record_len = struct.unpack_from("!H", data, 3)[0]
        assert len(data) == 5 + record_len

    def test_sni_contains_hostname(self):
        data = _build_client_hello(0, host="target.evil.com")
        assert b"target.evil.com" in data

    def test_tls13_probes_include_supported_versions(self):
        """Probes 3, 4, 5, 6 should include supported_versions extension."""
        for idx in (3, 4, 5, 6):
            data = _build_client_hello(idx, host="example.com")
            # supported_versions extension type = 0x002B
            assert b"\x00\x2b" in data, f"Probe {idx} missing supported_versions"

    def test_probe_9_includes_alpn_http11(self):
        data = _build_client_hello(9, host="example.com")
        assert b"http/1.1" in data

    def test_probe_3_includes_alpn_h2(self):
        data = _build_client_hello(3, host="example.com")
        assert b"h2" in data

    def test_all_probes_produce_distinct_payloads(self):
        """All 10 probes should produce different ClientHellos."""
        payloads = set()
        for i in range(10):
            data = _build_client_hello(i, host="example.com")
            payloads.add(data)
        assert len(payloads) == 10

    def test_record_layer_version(self):
        """Record layer version should be TLS 1.0 (0x0301) for all probes."""
        for i in range(10):
            data = _build_client_hello(i, host="example.com")
            record_version = struct.unpack_from("!H", data, 1)[0]
            assert record_version == 0x0301


# ─── _parse_server_hello ─────────────────────────────────────────────────────

def _make_server_hello(
    cipher: int = 0xC02F,
    version: int = 0x0303,
    extensions: bytes = b"",
) -> bytes:
    """Build a minimal ServerHello TLS record for testing."""
    # ServerHello body
    body = struct.pack("!H", version)     # server_version
    body += b"\x00" * 32                   # random
    body += b"\x00"                        # session_id length = 0
    body += struct.pack("!H", cipher)      # cipher_suite
    body += b"\x00"                        # compression_method = null

    if extensions:
        body += struct.pack("!H", len(extensions)) + extensions

    # Handshake wrapper
    hs = struct.pack("B", 0x02) + struct.pack("!I", len(body))[1:] + body

    # TLS record
    record = struct.pack("B", 0x16) + struct.pack("!H", 0x0303) + struct.pack("!H", len(hs)) + hs
    return record


class TestParseServerHello:

    def test_basic_parse(self):
        data = _make_server_hello(cipher=0xC02F, version=0x0303)
        result = _parse_server_hello(data)
        assert "c02f" in result
        assert "tls12" in result

    def test_tls13_via_supported_versions(self):
        """When supported_versions extension says TLS 1.3, version should be tls13."""
        ext = struct.pack("!HHH", 0x002B, 2, 0x0304)
        data = _make_server_hello(cipher=0x1301, version=0x0303, extensions=ext)
        result = _parse_server_hello(data)
        assert "1301" in result
        assert "tls13" in result

    def test_tls10(self):
        data = _make_server_hello(cipher=0x002F, version=0x0301)
        result = _parse_server_hello(data)
        assert "002f" in result
        assert "tls10" in result

    def test_empty_data_returns_separator(self):
        assert _parse_server_hello(b"") == "|||"

    def test_non_handshake_returns_separator(self):
        assert _parse_server_hello(b"\x15\x03\x03\x00\x02\x02\x00") == "|||"

    def test_truncated_data_returns_separator(self):
        assert _parse_server_hello(b"\x16\x03\x03") == "|||"

    def test_non_server_hello_returns_separator(self):
        """A Certificate message (type 0x0B) should not parse as ServerHello."""
        body = b"\x00" * 40
        hs = struct.pack("B", 0x0B) + struct.pack("!I", len(body))[1:] + body
        record = struct.pack("B", 0x16) + struct.pack("!H", 0x0303) + struct.pack("!H", len(hs)) + hs
        assert _parse_server_hello(record) == "|||"

    def test_extensions_in_output(self):
        ext = struct.pack("!HH", 0x0017, 0)  # extended_master_secret, no data
        data = _make_server_hello(cipher=0xC02F, version=0x0303, extensions=ext)
        result = _parse_server_hello(data)
        parts = result.split("|")
        assert len(parts) == 3
        assert "0017" in parts[2]


# ─── _compute_jarm ───────────────────────────────────────────────────────────

class TestComputeJarm:

    def test_all_failures_returns_empty_hash(self):
        responses = ["|||"] * 10
        assert _compute_jarm(responses) == JARM_EMPTY_HASH

    def test_hash_length_is_62(self):
        responses = ["c02f|tls12|0017"] * 10
        result = _compute_jarm(responses)
        assert len(result) == 62

    def test_deterministic(self):
        responses = ["c02f|tls12|0017-002b"] * 10
        r1 = _compute_jarm(responses)
        r2 = _compute_jarm(responses)
        assert r1 == r2

    def test_different_inputs_different_hashes(self):
        r1 = _compute_jarm(["c02f|tls12|0017"] * 10)
        r2 = _compute_jarm(["1301|tls13|002b"] * 10)
        assert r1 != r2

    def test_partial_failure(self):
        """Some probes fail, some succeed — should not be empty hash."""
        responses = ["c02f|tls12|0017"] * 5 + ["|||"] * 5
        result = _compute_jarm(responses)
        assert result != JARM_EMPTY_HASH
        assert len(result) == 62

    def test_first_30_chars_are_raw_components(self):
        responses = ["c02f|tls12|0017"] * 10
        result = _compute_jarm(responses)
        # "c02f" cipher → first 2 chars "c0", version tls12 → "c"
        # So each probe contributes "c0c" (3 chars), 10 probes = 30 chars
        raw_part = result[:30]
        assert raw_part == "c0c" * 10

    def test_last_32_chars_are_sha256(self):
        responses = ["c02f|tls12|0017"] * 10
        result = _compute_jarm(responses)
        ext_str = ",".join(["0017"] * 10)
        expected_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:32]
        assert result[30:] == expected_hash


# ─── _version_to_str ─────────────────────────────────────────────────────────

class TestVersionToStr:

    @pytest.mark.parametrize("version,expected", [
        (0x0304, "tls13"),
        (0x0303, "tls12"),
        (0x0302, "tls11"),
        (0x0301, "tls10"),
        (0x0300, "ssl30"),
        (0x9999, "9999"),
    ])
    def test_version_mapping(self, version: int, expected: str):
        assert _version_to_str(version) == expected


# ─── _middle_out ──────────────────────────────────────────────────────────────

class TestMiddleOut:

    def test_preserves_all_elements(self):
        original = list(range(10))
        result = _middle_out(original)
        assert sorted(result) == sorted(original)

    def test_starts_from_middle(self):
        original = list(range(10))
        result = _middle_out(original)
        assert result[0] == 5  # mid element


# ─── jarm_hash (end-to-end with mocked sockets) ─────────────────────────────

class TestJarmHashE2E:

    @patch("decnet.prober.jarm._send_probe")
    def test_all_probes_fail(self, mock_send: MagicMock):
        mock_send.return_value = None
        result = jarm_hash("1.2.3.4", 443, timeout=1.0)
        assert result == JARM_EMPTY_HASH
        assert mock_send.call_count == 10

    @patch("decnet.prober.jarm._send_probe")
    def test_all_probes_succeed(self, mock_send: MagicMock):
        server_hello = _make_server_hello(cipher=0xC02F, version=0x0303)
        mock_send.return_value = server_hello
        result = jarm_hash("1.2.3.4", 443, timeout=1.0)
        assert result != JARM_EMPTY_HASH
        assert len(result) == 62
        assert mock_send.call_count == 10

    @patch("decnet.prober.jarm._send_probe")
    def test_mixed_results(self, mock_send: MagicMock):
        server_hello = _make_server_hello(cipher=0x1301, version=0x0303)
        mock_send.side_effect = [server_hello, None] * 5
        result = jarm_hash("1.2.3.4", 443, timeout=1.0)
        assert result != JARM_EMPTY_HASH
        assert len(result) == 62

    @patch("decnet.prober.jarm.time.sleep")
    @patch("decnet.prober.jarm._send_probe")
    def test_inter_probe_delay(self, mock_send: MagicMock, mock_sleep: MagicMock):
        mock_send.return_value = None
        jarm_hash("1.2.3.4", 443, timeout=1.0)
        # Should sleep 9 times (between probes, not after last)
        assert mock_sleep.call_count == 9
