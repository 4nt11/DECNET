"""
Unit tests for the TCP/IP stack fingerprinting module.

Tests cover SYN-ACK parsing, options extraction, fingerprint computation,
and end-to-end tcp_fingerprint() with mocked scapy packets.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from decnet.prober.tcpfp import (
    _compute_fingerprint,
    _extract_options_order,
    _parse_synack,
    tcp_fingerprint,
)


# ─── Helpers ────────────────────────────────────────────────────────────────

def _make_synack(
    ttl: int = 64,
    flags: int = 0x02,  # IP flags (DF = 0x02)
    ip_id: int = 0,
    window: int = 65535,
    tcp_flags: int = 0x12,  # SYN-ACK
    options: list | None = None,
    ack: int = 1,
) -> SimpleNamespace:
    """Build a fake scapy-like SYN-ACK packet for testing."""
    if options is None:
        options = [
            ("MSS", 1460),
            ("NOP", None),
            ("WScale", 7),
            ("NOP", None),
            ("NOP", None),
            ("Timestamp", (12345, 0)),
            ("SAckOK", b""),
            ("EOL", None),
        ]

    tcp_layer = SimpleNamespace(
        flags=tcp_flags,
        window=window,
        options=options,
        dport=12345,
        ack=ack,
    )
    ip_layer = SimpleNamespace(
        ttl=ttl,
        flags=flags,
        id=ip_id,
    )

    class FakePacket:
        def __init__(self):
            self._layers = {"IP": ip_layer, "TCP": tcp_layer}
            self.ack = ack

        def __getitem__(self, key):
            # Support both class and string access
            name = key.__name__ if hasattr(key, "__name__") else str(key)
            return self._layers[name]

        def haslayer(self, key):
            name = key.__name__ if hasattr(key, "__name__") else str(key)
            return name in self._layers

    return FakePacket()


# ─── _extract_options_order ─────────────────────────────────────────────────

class TestExtractOptionsOrder:

    def test_standard_linux_options(self):
        options = [
            ("MSS", 1460), ("NOP", None), ("WScale", 7),
            ("NOP", None), ("NOP", None), ("Timestamp", (0, 0)),
            ("SAckOK", b""), ("EOL", None),
        ]
        assert _extract_options_order(options) == "M,N,W,N,N,T,S,E"

    def test_windows_options(self):
        options = [
            ("MSS", 1460), ("NOP", None), ("WScale", 8),
            ("NOP", None), ("NOP", None), ("SAckOK", b""),
        ]
        assert _extract_options_order(options) == "M,N,W,N,N,S"

    def test_empty_options(self):
        assert _extract_options_order([]) == ""

    def test_mss_only(self):
        assert _extract_options_order([("MSS", 536)]) == "M"

    def test_unknown_option(self):
        options = [("MSS", 1460), ("UnknownOpt", 42)]
        assert _extract_options_order(options) == "M,?"

    def test_sack_variant(self):
        options = [("SAck", (100, 200))]
        assert _extract_options_order(options) == "S"


# ─── _parse_synack ──────────────────────────────────────────────────────────

class TestParseSynack:

    def test_linux_64_ttl(self):
        resp = _make_synack(ttl=64)
        result = _parse_synack(resp)
        assert result["ttl"] == 64

    def test_windows_128_ttl(self):
        resp = _make_synack(ttl=128)
        result = _parse_synack(resp)
        assert result["ttl"] == 128

    def test_df_bit_set(self):
        resp = _make_synack(flags=0x02)  # DF set
        result = _parse_synack(resp)
        assert result["df_bit"] == 1

    def test_df_bit_unset(self):
        resp = _make_synack(flags=0x00)
        result = _parse_synack(resp)
        assert result["df_bit"] == 0

    def test_window_size(self):
        resp = _make_synack(window=29200)
        result = _parse_synack(resp)
        assert result["window_size"] == 29200

    def test_mss_extraction(self):
        resp = _make_synack(options=[("MSS", 1460)])
        result = _parse_synack(resp)
        assert result["mss"] == 1460

    def test_window_scale(self):
        resp = _make_synack(options=[("WScale", 7)])
        result = _parse_synack(resp)
        assert result["window_scale"] == 7

    def test_sack_ok(self):
        resp = _make_synack(options=[("SAckOK", b"")])
        result = _parse_synack(resp)
        assert result["sack_ok"] == 1

    def test_no_sack(self):
        resp = _make_synack(options=[("MSS", 1460)])
        result = _parse_synack(resp)
        assert result["sack_ok"] == 0

    def test_timestamp_present(self):
        resp = _make_synack(options=[("Timestamp", (12345, 0))])
        result = _parse_synack(resp)
        assert result["timestamp"] == 1

    def test_no_timestamp(self):
        resp = _make_synack(options=[("MSS", 1460)])
        result = _parse_synack(resp)
        assert result["timestamp"] == 0

    def test_options_order(self):
        resp = _make_synack(options=[
            ("MSS", 1460), ("NOP", None), ("WScale", 7),
            ("SAckOK", b""), ("Timestamp", (0, 0)),
        ])
        result = _parse_synack(resp)
        assert result["options_order"] == "M,N,W,S,T"

    def test_ip_id(self):
        resp = _make_synack(ip_id=12345)
        result = _parse_synack(resp)
        assert result["ip_id"] == 12345

    def test_empty_options(self):
        resp = _make_synack(options=[])
        result = _parse_synack(resp)
        assert result["mss"] == 0
        assert result["window_scale"] == -1
        assert result["sack_ok"] == 0
        assert result["timestamp"] == 0
        assert result["options_order"] == ""

    def test_full_linux_fingerprint(self):
        """Typical Linux 5.x+ SYN-ACK."""
        resp = _make_synack(
            ttl=64, flags=0x02, window=65535,
            options=[
                ("MSS", 1460), ("NOP", None), ("WScale", 7),
                ("NOP", None), ("NOP", None), ("Timestamp", (0, 0)),
                ("SAckOK", b""), ("EOL", None),
            ],
        )
        result = _parse_synack(resp)
        assert result["ttl"] == 64
        assert result["df_bit"] == 1
        assert result["window_size"] == 65535
        assert result["mss"] == 1460
        assert result["window_scale"] == 7
        assert result["sack_ok"] == 1
        assert result["timestamp"] == 1
        assert result["options_order"] == "M,N,W,N,N,T,S,E"


# ─── _compute_fingerprint ──────────────────────────────────────────────────

class TestComputeFingerprint:

    def test_hash_length_is_32(self):
        fields = {
            "ttl": 64, "window_size": 65535, "df_bit": 1,
            "mss": 1460, "window_scale": 7, "sack_ok": 1,
            "timestamp": 1, "options_order": "M,N,W,N,N,T,S,E",
        }
        raw, h = _compute_fingerprint(fields)
        assert len(h) == 32

    def test_deterministic(self):
        fields = {
            "ttl": 64, "window_size": 65535, "df_bit": 1,
            "mss": 1460, "window_scale": 7, "sack_ok": 1,
            "timestamp": 1, "options_order": "M,N,W,S,T",
        }
        _, h1 = _compute_fingerprint(fields)
        _, h2 = _compute_fingerprint(fields)
        assert h1 == h2

    def test_different_inputs_different_hashes(self):
        f1 = {
            "ttl": 64, "window_size": 65535, "df_bit": 1,
            "mss": 1460, "window_scale": 7, "sack_ok": 1,
            "timestamp": 1, "options_order": "M,N,W,S,T",
        }
        f2 = {
            "ttl": 128, "window_size": 8192, "df_bit": 1,
            "mss": 1460, "window_scale": 8, "sack_ok": 1,
            "timestamp": 0, "options_order": "M,N,W,N,N,S",
        }
        _, h1 = _compute_fingerprint(f1)
        _, h2 = _compute_fingerprint(f2)
        assert h1 != h2

    def test_raw_format(self):
        fields = {
            "ttl": 64, "window_size": 65535, "df_bit": 1,
            "mss": 1460, "window_scale": 7, "sack_ok": 1,
            "timestamp": 1, "options_order": "M,N,W",
        }
        raw, _ = _compute_fingerprint(fields)
        assert raw == "64:65535:1:1460:7:1:1:M,N,W"

    def test_sha256_correctness(self):
        fields = {
            "ttl": 64, "window_size": 65535, "df_bit": 1,
            "mss": 1460, "window_scale": 7, "sack_ok": 1,
            "timestamp": 1, "options_order": "M,N,W",
        }
        raw, h = _compute_fingerprint(fields)
        expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        assert h == expected


# ─── tcp_fingerprint (end-to-end with mocked scapy) ────────────────────────

class TestTcpFingerprintE2E:

    @patch("decnet.prober.tcpfp._send_syn")
    def test_success(self, mock_send: MagicMock):
        mock_send.return_value = _make_synack(
            ttl=64, flags=0x02, window=65535,
            options=[
                ("MSS", 1460), ("NOP", None), ("WScale", 7),
                ("SAckOK", b""), ("Timestamp", (0, 0)),
            ],
        )
        result = tcp_fingerprint("10.0.0.1", 443, timeout=1.0)
        assert result is not None
        assert len(result["tcpfp_hash"]) == 32
        assert result["ttl"] == 64
        assert result["window_size"] == 65535
        assert result["df_bit"] == 1
        assert result["mss"] == 1460
        assert result["window_scale"] == 7
        assert result["sack_ok"] == 1
        assert result["timestamp"] == 1
        assert result["options_order"] == "M,N,W,S,T"

    @patch("decnet.prober.tcpfp._send_syn")
    def test_no_response_returns_none(self, mock_send: MagicMock):
        mock_send.return_value = None
        assert tcp_fingerprint("10.0.0.1", 443, timeout=1.0) is None

    @patch("decnet.prober.tcpfp._send_syn")
    def test_windows_fingerprint(self, mock_send: MagicMock):
        mock_send.return_value = _make_synack(
            ttl=128, flags=0x02, window=8192,
            options=[
                ("MSS", 1460), ("NOP", None), ("WScale", 8),
                ("NOP", None), ("NOP", None), ("SAckOK", b""),
            ],
        )
        result = tcp_fingerprint("10.0.0.1", 443, timeout=1.0)
        assert result is not None
        assert result["ttl"] == 128
        assert result["window_size"] == 8192
        assert result["window_scale"] == 8

    @patch("decnet.prober.tcpfp._send_syn")
    def test_embedded_device_fingerprint(self, mock_send: MagicMock):
        """Embedded devices often have TTL=255, small window, no options."""
        mock_send.return_value = _make_synack(
            ttl=255, flags=0x00, window=4096,
            options=[("MSS", 536)],
        )
        result = tcp_fingerprint("10.0.0.1", 80, timeout=1.0)
        assert result is not None
        assert result["ttl"] == 255
        assert result["df_bit"] == 0
        assert result["window_size"] == 4096
        assert result["mss"] == 536
        assert result["window_scale"] == -1
        assert result["sack_ok"] == 0

    @patch("decnet.prober.tcpfp._send_syn")
    def test_result_contains_raw_and_hash(self, mock_send: MagicMock):
        mock_send.return_value = _make_synack()
        result = tcp_fingerprint("10.0.0.1", 443)
        assert "tcpfp_hash" in result
        assert "tcpfp_raw" in result
        assert ":" in result["tcpfp_raw"]

    @patch("decnet.prober.tcpfp._send_syn")
    def test_deterministic(self, mock_send: MagicMock):
        pkt = _make_synack(ttl=64, window=65535)
        mock_send.return_value = pkt

        r1 = tcp_fingerprint("10.0.0.1", 443)
        r2 = tcp_fingerprint("10.0.0.1", 443)
        assert r1["tcpfp_hash"] == r2["tcpfp_hash"]
        assert r1["tcpfp_raw"] == r2["tcpfp_raw"]
