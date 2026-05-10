"""Tests for QUIC v1 Initial packet key derivation (RFC 9001 Appendix A vectors)."""
from __future__ import annotations

import pytest

from decnet.sniffer.fingerprint import (
    _hkdf_extract,
    _hkdf_expand_label,
    _quic_initial_keys,
    _QUIC_V1_INITIAL_SALT,
    _ja4_quic,
    _parse_quic_initial,
)


# RFC 9001 Appendix A.1 key derivation test vectors
_RFC9001_DCID = bytes.fromhex("8394c8f03e515708")
_RFC9001_CLIENT_KEY = bytes.fromhex("1f369613dd76d5467730efcbe3b1a22d")
_RFC9001_CLIENT_IV = bytes.fromhex("fa044b2f42a3fd3b46fb255c")
_RFC9001_CLIENT_HP = bytes.fromhex("9f50449e04a0e810283a1e9933adedd2")


class TestHKDF:
    def test_extract_sha256(self):
        # HKDF-Extract is HMAC-SHA256(salt, IKM). Cross-check with a known value.
        result = _hkdf_extract(b"salt", b"ikm")
        import hmac, hashlib
        expected = hmac.new(b"salt", b"ikm", hashlib.sha256).digest()
        assert result == expected

    def test_expand_label_length(self):
        secret = _hkdf_extract(_QUIC_V1_INITIAL_SALT, _RFC9001_DCID)
        # "client in" expand should be 32 bytes
        client_secret = _hkdf_expand_label(secret, "client in", b"", 32)
        assert len(client_secret) == 32

    def test_expand_label_key_length(self):
        secret = _hkdf_extract(_QUIC_V1_INITIAL_SALT, _RFC9001_DCID)
        client_secret = _hkdf_expand_label(secret, "client in", b"", 32)
        key = _hkdf_expand_label(client_secret, "quic key", b"", 16)
        assert len(key) == 16

    def test_expand_label_iv_length(self):
        secret = _hkdf_extract(_QUIC_V1_INITIAL_SALT, _RFC9001_DCID)
        client_secret = _hkdf_expand_label(secret, "client in", b"", 32)
        iv = _hkdf_expand_label(client_secret, "quic iv", b"", 12)
        assert len(iv) == 12


class TestQuicInitialKeys:
    def test_rfc9001_appendix_a_vectors(self):
        """Key derivation must match RFC 9001 Appendix A.1 test vectors exactly."""
        key, iv, hp = _quic_initial_keys(_RFC9001_DCID)
        assert key == _RFC9001_CLIENT_KEY, f"key mismatch: {key.hex()}"
        assert iv == _RFC9001_CLIENT_IV, f"iv mismatch: {iv.hex()}"
        assert hp == _RFC9001_CLIENT_HP, f"hp mismatch: {hp.hex()}"


class TestJA4Quic:
    def test_proto_prefix_is_q(self):
        ch = {
            "cipher_suites": [0x1301, 0x1302],
            "extensions": [0x000a, 0x000d, 0x002b],
            "signature_algorithms": [0x0403, 0x0804],
            "supported_versions": [0x0304],
            "sni": "example.com",
            "alpn": ["h3"],
            "tls_version": 0x0303,
        }
        result = _ja4_quic(ch)
        assert result.startswith("q"), f"expected 'q' prefix: {result}"

    def test_structure(self):
        ch = {
            "cipher_suites": [0x1301],
            "extensions": [0x000a],
            "signature_algorithms": [],
            "supported_versions": [0x0304],
            "sni": "",
            "alpn": [],
            "tls_version": 0x0303,
        }
        result = _ja4_quic(ch)
        parts = result.split("_")
        assert len(parts) == 3

    def test_deterministic(self):
        ch = {
            "cipher_suites": [0x1301, 0x1302, 0x1303],
            "extensions": [0x000a, 0x000d],
            "signature_algorithms": [0x0403],
            "supported_versions": [0x0304],
            "sni": "host.example",
            "alpn": ["h3"],
            "tls_version": 0x0303,
        }
        assert _ja4_quic(ch) == _ja4_quic(ch)


class TestParseQuicInitial:
    def test_short_header_rejected(self):
        # Short header: bit 7 clear
        assert _parse_quic_initial(b"\x40" + b"\x00" * 20) is None

    def test_wrong_version_rejected(self):
        # Long header, Initial type, version = 0x00000002
        pkt = bytearray(30)
        pkt[0] = 0xC0  # long header + Initial
        pkt[1:5] = b"\x00\x00\x00\x02"  # version 2
        assert _parse_quic_initial(bytes(pkt)) is None

    def test_non_initial_type_rejected(self):
        # Long header, Handshake type (0x20 set)
        pkt = bytearray(30)
        pkt[0] = 0xE0  # long header + Handshake
        pkt[1:5] = b"\x00\x00\x00\x01"
        assert _parse_quic_initial(bytes(pkt)) is None

    def test_garbage_returns_none(self):
        assert _parse_quic_initial(b"garbage bytes that are not QUIC") is None

    def test_too_short_returns_none(self):
        assert _parse_quic_initial(b"\xc0\x00") is None
