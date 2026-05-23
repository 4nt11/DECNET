# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for the passive p0f-lite OS fingerprint lookup.

Covers:
    - initial_ttl() TTL → bucket rounding
    - hop_distance() upper-bound clamping
    - guess_os() signature matching for Linux, Windows, macOS, nmap,
      embedded, and the unknown fallback
"""

from __future__ import annotations

from decnet.sniffer.p0f import guess_os, hop_distance, initial_ttl


# ─── initial_ttl ────────────────────────────────────────────────────────────

class TestInitialTtl:
    def test_linux_bsd(self):
        assert initial_ttl(64) == 64
        assert initial_ttl(59) == 64
        assert initial_ttl(33) == 64

    def test_windows(self):
        assert initial_ttl(128) == 128
        assert initial_ttl(120) == 128
        assert initial_ttl(65) == 128

    def test_embedded(self):
        assert initial_ttl(255) == 255
        assert initial_ttl(254) == 255
        assert initial_ttl(200) == 255

    def test_very_short(self):
        # anything <= 32 rounds to 32
        assert initial_ttl(32) == 32
        assert initial_ttl(1) == 32

    def test_out_of_range(self):
        # Packets with TTL > 255 (should never happen) still bucket.
        assert initial_ttl(300) == 255


# ─── hop_distance ───────────────────────────────────────────────────────────

class TestHopDistance:
    def test_zero_when_local(self):
        assert hop_distance(64) == 0
        assert hop_distance(128) == 0
        assert hop_distance(255) == 0

    def test_typical(self):
        assert hop_distance(60) == 4  # 4 hops from Linux
        assert hop_distance(120) == 8  # 8 hops from Windows

    def test_negative_or_weird_still_bucketed(self):
        # TTL=0 is anomalous but we still return a non-negative distance.
        # TTL 0 bucket is 32 → distance = 32 - 0 = 32.
        assert hop_distance(0) == 32


# ─── guess_os ───────────────────────────────────────────────────────────────

class TestGuessOs:
    def test_linux_default(self):
        # Modern Linux: TTL 64, window 29200+, WScale 7, full options
        result = guess_os(
            ttl=64, window=29200, mss=1460, wscale=7,
            options_sig="M,S,T,N,W",
        )
        assert result == "linux"

    def test_windows_default(self):
        # Windows 10: TTL 128, window 64240, WScale 8, MSS 1460
        result = guess_os(
            ttl=128, window=64240, mss=1460, wscale=8,
            options_sig="M,N,W,N,N,T,S",
        )
        assert result == "windows"

    def test_macos_ios(self):
        # macOS default: TTL 64, window 65535, WScale 6, ends with EOL
        result = guess_os(
            ttl=64, window=65535, mss=1460, wscale=6,
            options_sig="M,N,W,N,N,T,S,E",
        )
        assert result == "macos_ios"

    def test_nmap_sYn(self):
        # nmap -sS uses tiny/distinctive windows like 1024 or 4096
        result = guess_os(
            ttl=64, window=1024, mss=1460, wscale=10,
            options_sig="M,W,T,S,S",
        )
        assert result == "nmap"

    def test_nmap_alt_window(self):
        result = guess_os(
            ttl=64, window=31337, mss=1460, wscale=10,
            options_sig="M,W,T,S,S",
        )
        assert result == "nmap"

    def test_embedded_ttl255(self):
        # Any TTL bucket 255 → embedded
        result = guess_os(
            ttl=250, window=4128, mss=536, wscale=None,
            options_sig="M",
        )
        assert result == "embedded"

    def test_unknown(self):
        # Bizarre combo nothing matches
        result = guess_os(
            ttl=50, window=100, mss=0, wscale=None, options_sig="",
        )
        assert result == "unknown"
