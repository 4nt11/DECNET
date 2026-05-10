"""Tests for _ja4h computation and QUIC helpers in decnet.sniffer.fingerprint."""
from __future__ import annotations

import pytest

from decnet.sniffer.fingerprint import _ja4h, _quic_varint, _extract_crypto_frames


class TestJA4H:
    def test_basic_get_h11(self):
        result = _ja4h(
            method="GET",
            version="HTTP/1.1",
            headers_ordered=["Host", "User-Agent", "Accept"],
        )
        parts = result.split("_")
        assert len(parts) == 4
        assert parts[0].startswith("GE11")  # method + version
        assert parts[0][4] == "n"           # no cookie
        assert parts[0][5] == "n"           # no referer
        assert parts[0][6:10] == "0000"     # no Accept-Language

    def test_cookie_flag(self):
        result = _ja4h(
            method="POST",
            version="HTTP/1.1",
            headers_ordered=["Host", "Cookie", "Content-Type"],
            cookie_val="session=abc",
        )
        parts = result.split("_")
        assert parts[0][4] == "c"           # has cookie
        assert parts[0][5] == "n"           # no referer

    def test_referer_flag(self):
        result = _ja4h(
            method="GET",
            version="HTTP/1.1",
            headers_ordered=["Host", "Referer"],
        )
        parts = result.split("_")
        assert parts[0][5] == "r"           # has referer

    def test_h2_version_tag(self):
        result = _ja4h(
            method="GET",
            version="HTTP/2.0",
            headers_ordered=["Host", "User-Agent"],
        )
        assert result.startswith("GE20")

    def test_h3_version_tag(self):
        result = _ja4h(
            method="GET",
            version="HTTP/3.0",
            headers_ordered=["Host", "User-Agent"],
        )
        assert result.startswith("GE30")

    def test_cookie_and_referer_excluded_from_header_hash(self):
        result_with = _ja4h(
            method="GET",
            version="HTTP/1.1",
            headers_ordered=["Host", "User-Agent", "Cookie", "Referer"],
            cookie_val="x=1",
        )
        result_without = _ja4h(
            method="GET",
            version="HTTP/1.1",
            headers_ordered=["Host", "User-Agent"],
        )
        # Header hash (parts[2]) must be identical — cookie/referer excluded from it
        assert result_with.split("_")[2] == result_without.split("_")[2]

    def test_header_count_excludes_cookie_and_referer(self):
        result = _ja4h(
            method="GET",
            version="HTTP/1.1",
            headers_ordered=["Host", "Cookie", "Accept", "Referer"],
        )
        parts = result.split("_")
        # 2 headers after dropping Cookie and Referer (Host + Accept)
        assert parts[1] == "02"

    def test_cookie_hash_alphabetical_sort(self):
        r1 = _ja4h("GET", "HTTP/1.1", [], cookie_val="z=3; a=1; m=2")
        r2 = _ja4h("GET", "HTTP/1.1", [], cookie_val="a=1; m=2; z=3")
        # Both should produce the same cookie hash regardless of original order
        assert r1.split("_")[3] == r2.split("_")[3]

    def test_no_cookie_produces_12_zeros(self):
        result = _ja4h("GET", "HTTP/1.1", ["Host"])
        assert result.split("_")[3] == "000000000000"

    def test_accept_lang_truncated_to_4_chars(self):
        result = _ja4h("GET", "HTTP/1.1", [], accept_lang="en-US,en;q=0.9")
        parts = result.split("_")
        lang_tag = parts[0][6:10]
        assert lang_tag == "en-U"

    def test_deterministic(self):
        kwargs = dict(
            method="POST",
            version="HTTP/1.1",
            headers_ordered=["Host", "Content-Type", "Accept"],
        )
        assert _ja4h(**kwargs) == _ja4h(**kwargs)


class TestQuicVarint:
    def test_1_byte(self):
        assert _quic_varint(b"\x3f", 0) == (63, 1)

    def test_2_byte(self):
        # 0x4000 → big 2-byte form: 01 + 14 bits = 0x4000 = 16384
        data = bytes([0x40, 0x00])
        assert _quic_varint(data, 0) == (0, 2)

    def test_4_byte(self):
        # 0x80000000 → 2 MSB = 10, value = 0
        data = bytes([0x80, 0x00, 0x00, 0x00])
        assert _quic_varint(data, 0) == (0, 4)

    def test_small_values(self):
        assert _quic_varint(b"\x00", 0) == (0, 1)
        assert _quic_varint(b"\x01", 0) == (1, 1)
        assert _quic_varint(b"\x25", 0) == (37, 1)


class TestExtractCryptoFrames:
    def test_single_crypto_frame(self):
        # CRYPTO frame: type=0x06, offset=0x00 (varint), length=5 (varint), data
        data_bytes = b"hello"
        frame = bytes([0x06, 0x00, 0x05]) + data_bytes
        result = _extract_crypto_frames(frame)
        assert result == b"hello"

    def test_empty_payload(self):
        result = _extract_crypto_frames(b"")
        assert result == b""

    def test_padding_skipped(self):
        # PADDING (0x00) + CRYPTO frame
        data_bytes = b"world"
        frame = bytes([0x00, 0x00, 0x06, 0x00, 0x05]) + data_bytes
        result = _extract_crypto_frames(frame)
        assert result == b"world"

    def test_non_crypto_frame_stops_parsing(self):
        # Unknown frame type (0x10) after CRYPTO — should stop and return what we have
        data = b"hello"
        frame = bytes([0x06, 0x00, 0x05]) + data + bytes([0x10, 0x00])
        result = _extract_crypto_frames(frame)
        assert result == b"hello"
