"""
Unit tests for the HASSHServer SSH fingerprinting module.

Tests cover KEX_INIT parsing, HASSH hash computation, SSH connection
handling, and end-to-end hassh_server() with mocked sockets.
"""

from __future__ import annotations

import hashlib
import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from decnet.prober.hassh import (
    _CLIENT_BANNER,
    _SSH_MSG_KEXINIT,
    _compute_hassh,
    _parse_kex_init,
    _read_banner,
    _read_ssh_packet,
    hassh_server,
)


# ─── Helpers ────────────────────────────────────────────────────────────────

def _build_name_list(value: str) -> bytes:
    """Encode a single SSH name-list (uint32 length + utf-8 string)."""
    encoded = value.encode("utf-8")
    return struct.pack("!I", len(encoded)) + encoded


def _build_kex_init(
    kex: str = "curve25519-sha256,diffie-hellman-group14-sha256",
    host_key: str = "ssh-ed25519,rsa-sha2-512",
    enc_c2s: str = "aes256-gcm@openssh.com,aes128-gcm@openssh.com",
    enc_s2c: str = "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
    mac_c2s: str = "hmac-sha2-256-etm@openssh.com",
    mac_s2c: str = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
    comp_c2s: str = "none,zlib@openssh.com",
    comp_s2c: str = "none,zlib@openssh.com",
    lang_c2s: str = "",
    lang_s2c: str = "",
    cookie: bytes | None = None,
) -> bytes:
    """Build a complete SSH_MSG_KEXINIT payload for testing."""
    if cookie is None:
        cookie = b"\x00" * 16

    payload = struct.pack("B", _SSH_MSG_KEXINIT) + cookie
    for value in [kex, host_key, enc_c2s, enc_s2c, mac_c2s, mac_s2c,
                  comp_c2s, comp_s2c, lang_c2s, lang_s2c]:
        payload += _build_name_list(value)
    # first_kex_packet_follows (bool) + reserved (uint32)
    payload += struct.pack("!BI", 0, 0)
    return payload


def _wrap_ssh_packet(payload: bytes) -> bytes:
    """Wrap payload into an SSH binary packet (header only, no MAC)."""
    # Padding to 8-byte boundary (minimum 4 bytes)
    block_size = 8
    padding_needed = block_size - ((1 + len(payload)) % block_size)
    if padding_needed < 4:
        padding_needed += block_size
    padding = b"\x00" * padding_needed
    packet_length = 1 + len(payload) + len(padding)  # padding_length(1) + payload + padding
    return struct.pack("!IB", packet_length, padding_needed) + payload + padding


def _make_socket_with_data(data: bytes) -> MagicMock:
    """Create a mock socket that yields data byte-by-byte or in chunks."""
    sock = MagicMock()
    pos = [0]

    def recv(n):
        if pos[0] >= len(data):
            return b""
        chunk = data[pos[0] : pos[0] + n]
        pos[0] += n
        return chunk

    sock.recv = recv
    return sock


# ─── _parse_kex_init ────────────────────────────────────────────────────────

class TestParseKexInit:

    def test_parses_all_ten_fields(self):
        payload = _build_kex_init()
        result = _parse_kex_init(payload)
        assert result is not None
        assert len(result) == 10

    def test_extracts_correct_field_values(self):
        payload = _build_kex_init(
            kex="curve25519-sha256",
            enc_s2c="chacha20-poly1305@openssh.com",
            mac_s2c="hmac-sha2-512-etm@openssh.com",
            comp_s2c="none",
        )
        result = _parse_kex_init(payload)
        assert result["kex_algorithms"] == "curve25519-sha256"
        assert result["encryption_server_to_client"] == "chacha20-poly1305@openssh.com"
        assert result["mac_server_to_client"] == "hmac-sha2-512-etm@openssh.com"
        assert result["compression_server_to_client"] == "none"

    def test_extracts_hassh_server_fields_at_correct_indices(self):
        """HASSHServer uses indices 0(kex), 3(enc_s2c), 5(mac_s2c), 7(comp_s2c)."""
        payload = _build_kex_init(
            kex="KEX_FIELD",
            host_key="HOSTKEY_FIELD",
            enc_c2s="ENC_C2S_FIELD",
            enc_s2c="ENC_S2C_FIELD",
            mac_c2s="MAC_C2S_FIELD",
            mac_s2c="MAC_S2C_FIELD",
            comp_c2s="COMP_C2S_FIELD",
            comp_s2c="COMP_S2C_FIELD",
        )
        result = _parse_kex_init(payload)
        # Indices used by HASSHServer
        assert result["kex_algorithms"] == "KEX_FIELD"               # index 0
        assert result["encryption_server_to_client"] == "ENC_S2C_FIELD"  # index 3
        assert result["mac_server_to_client"] == "MAC_S2C_FIELD"     # index 5
        assert result["compression_server_to_client"] == "COMP_S2C_FIELD"  # index 7

    def test_empty_name_lists(self):
        payload = _build_kex_init(
            kex="", host_key="", enc_c2s="", enc_s2c="",
            mac_c2s="", mac_s2c="", comp_c2s="", comp_s2c="",
        )
        result = _parse_kex_init(payload)
        assert result is not None
        assert result["kex_algorithms"] == ""

    def test_truncated_payload_returns_none(self):
        # Just the type byte and cookie, no name-lists
        payload = struct.pack("B", _SSH_MSG_KEXINIT) + b"\x00" * 16
        assert _parse_kex_init(payload) is None

    def test_truncated_name_list_returns_none(self):
        # Type + cookie + length says 100 but only 2 bytes follow
        payload = struct.pack("B", _SSH_MSG_KEXINIT) + b"\x00" * 16
        payload += struct.pack("!I", 100) + b"ab"
        assert _parse_kex_init(payload) is None

    def test_too_short_returns_none(self):
        assert _parse_kex_init(b"") is None
        assert _parse_kex_init(b"\x14") is None

    def test_large_algorithm_lists(self):
        long_kex = ",".join(f"algo-{i}" for i in range(50))
        payload = _build_kex_init(kex=long_kex)
        result = _parse_kex_init(payload)
        assert result is not None
        assert result["kex_algorithms"] == long_kex


# ─── _compute_hassh ─────────────────────────────────────────────────────────

class TestComputeHashh:

    def test_md5_correctness(self):
        kex = "curve25519-sha256"
        enc = "aes256-gcm@openssh.com"
        mac = "hmac-sha2-256-etm@openssh.com"
        comp = "none"
        raw = f"{kex};{enc};{mac};{comp}"
        expected = hashlib.md5(raw.encode("utf-8")).hexdigest()
        assert _compute_hassh(kex, enc, mac, comp) == expected

    def test_hash_length_is_32(self):
        result = _compute_hassh("a", "b", "c", "d")
        assert len(result) == 32

    def test_deterministic(self):
        r1 = _compute_hassh("kex1", "enc1", "mac1", "comp1")
        r2 = _compute_hassh("kex1", "enc1", "mac1", "comp1")
        assert r1 == r2

    def test_different_inputs_different_hashes(self):
        r1 = _compute_hassh("kex1", "enc1", "mac1", "comp1")
        r2 = _compute_hassh("kex2", "enc2", "mac2", "comp2")
        assert r1 != r2

    def test_empty_fields(self):
        result = _compute_hassh("", "", "", "")
        expected = hashlib.md5(b";;;").hexdigest()
        assert result == expected

    def test_semicolon_delimiter(self):
        """The delimiter is semicolon, not comma."""
        result = _compute_hassh("a", "b", "c", "d")
        expected = hashlib.md5(b"a;b;c;d").hexdigest()
        assert result == expected


# ─── _read_banner ───────────────────────────────────────────────────────────

class TestReadBanner:

    def test_reads_banner_with_crlf(self):
        sock = _make_socket_with_data(b"SSH-2.0-OpenSSH_8.9p1\r\n")
        result = _read_banner(sock)
        assert result == "SSH-2.0-OpenSSH_8.9p1"

    def test_reads_banner_with_lf(self):
        sock = _make_socket_with_data(b"SSH-2.0-OpenSSH_8.9p1\n")
        result = _read_banner(sock)
        assert result == "SSH-2.0-OpenSSH_8.9p1"

    def test_empty_data_returns_none(self):
        sock = _make_socket_with_data(b"")
        result = _read_banner(sock)
        assert result is None

    def test_no_newline_within_limit(self):
        # 256 bytes with no newline — should stop at limit
        sock = _make_socket_with_data(b"A" * 256)
        result = _read_banner(sock)
        assert result == "A" * 256


# ─── _read_ssh_packet ───────────────────────────────────────────────────────

class TestReadSSHPacket:

    def test_reads_valid_packet(self):
        payload = b"\x14" + b"\x00" * 20  # type 20 + some data
        packet_data = _wrap_ssh_packet(payload)
        sock = _make_socket_with_data(packet_data)
        result = _read_ssh_packet(sock)
        assert result is not None
        assert result[0] == 0x14  # SSH_MSG_KEXINIT

    def test_empty_socket_returns_none(self):
        sock = _make_socket_with_data(b"")
        assert _read_ssh_packet(sock) is None

    def test_truncated_header_returns_none(self):
        sock = _make_socket_with_data(b"\x00\x00")
        assert _read_ssh_packet(sock) is None

    def test_oversized_packet_returns_none(self):
        # packet_length = 40000 (over limit)
        sock = _make_socket_with_data(struct.pack("!I", 40000))
        assert _read_ssh_packet(sock) is None

    def test_zero_length_returns_none(self):
        sock = _make_socket_with_data(struct.pack("!I", 0))
        assert _read_ssh_packet(sock) is None


# ─── hassh_server (end-to-end with mocked sockets) ─────────────────────────

class TestHasshServerE2E:

    @patch("decnet.prober.hassh._ssh_connect")
    def test_success(self, mock_connect: MagicMock):
        payload = _build_kex_init(
            kex="curve25519-sha256",
            enc_s2c="aes256-gcm@openssh.com",
            mac_s2c="hmac-sha2-256-etm@openssh.com",
            comp_s2c="none",
        )
        mock_connect.return_value = ("SSH-2.0-OpenSSH_8.9p1", payload)

        result = hassh_server("10.0.0.1", 22, timeout=1.0)
        assert result is not None
        assert len(result["hassh_server"]) == 32
        assert result["banner"] == "SSH-2.0-OpenSSH_8.9p1"
        assert result["kex_algorithms"] == "curve25519-sha256"
        assert result["encryption_s2c"] == "aes256-gcm@openssh.com"
        assert result["mac_s2c"] == "hmac-sha2-256-etm@openssh.com"
        assert result["compression_s2c"] == "none"

    @patch("decnet.prober.hassh._ssh_connect")
    def test_connection_failure_returns_none(self, mock_connect: MagicMock):
        mock_connect.return_value = None
        assert hassh_server("10.0.0.1", 22, timeout=1.0) is None

    @patch("decnet.prober.hassh._ssh_connect")
    def test_truncated_kex_init_returns_none(self, mock_connect: MagicMock):
        # Payload too short to parse
        payload = struct.pack("B", _SSH_MSG_KEXINIT) + b"\x00" * 16
        mock_connect.return_value = ("SSH-2.0-OpenSSH_8.9p1", payload)
        assert hassh_server("10.0.0.1", 22, timeout=1.0) is None

    @patch("decnet.prober.hassh._ssh_connect")
    def test_hash_is_deterministic(self, mock_connect: MagicMock):
        payload = _build_kex_init()
        mock_connect.return_value = ("SSH-2.0-OpenSSH_8.9p1", payload)

        r1 = hassh_server("10.0.0.1", 22)
        r2 = hassh_server("10.0.0.1", 22)
        assert r1["hassh_server"] == r2["hassh_server"]

    @patch("decnet.prober.hassh._ssh_connect")
    def test_different_servers_different_hashes(self, mock_connect: MagicMock):
        p1 = _build_kex_init(kex="curve25519-sha256", enc_s2c="aes256-gcm@openssh.com")
        p2 = _build_kex_init(kex="diffie-hellman-group14-sha1", enc_s2c="aes128-cbc")

        mock_connect.return_value = ("SSH-2.0-OpenSSH_8.9p1", p1)
        r1 = hassh_server("10.0.0.1", 22)

        mock_connect.return_value = ("SSH-2.0-Paramiko_3.0", p2)
        r2 = hassh_server("10.0.0.2", 22)

        assert r1["hassh_server"] != r2["hassh_server"]

    @patch("decnet.prober.hassh.socket.create_connection")
    def test_full_socket_mock(self, mock_create: MagicMock):
        """Full integration: mock at socket level, verify banner exchange."""
        kex_payload = _build_kex_init()
        kex_packet = _wrap_ssh_packet(kex_payload)

        banner_bytes = b"SSH-2.0-OpenSSH_8.9p1\r\n"
        all_data = banner_bytes + kex_packet

        mock_sock = _make_socket_with_data(all_data)
        mock_sock.sendall = MagicMock()
        mock_sock.settimeout = MagicMock()
        mock_sock.close = MagicMock()
        mock_create.return_value = mock_sock

        result = hassh_server("10.0.0.1", 22, timeout=2.0)
        assert result is not None
        assert result["banner"] == "SSH-2.0-OpenSSH_8.9p1"
        assert len(result["hassh_server"]) == 32

        # Verify we sent our client banner
        mock_sock.sendall.assert_called_once_with(_CLIENT_BANNER)

    @patch("decnet.prober.hassh.socket.create_connection")
    def test_non_ssh_banner_returns_none(self, mock_create: MagicMock):
        mock_sock = _make_socket_with_data(b"HTTP/1.1 200 OK\r\n")
        mock_sock.sendall = MagicMock()
        mock_sock.settimeout = MagicMock()
        mock_sock.close = MagicMock()
        mock_create.return_value = mock_sock

        assert hassh_server("10.0.0.1", 80, timeout=1.0) is None

    @patch("decnet.prober.hassh.socket.create_connection")
    def test_connection_refused(self, mock_create: MagicMock):
        mock_create.side_effect = ConnectionRefusedError
        assert hassh_server("10.0.0.1", 22, timeout=1.0) is None

    @patch("decnet.prober.hassh.socket.create_connection")
    def test_timeout(self, mock_create: MagicMock):
        mock_create.side_effect = socket.timeout("timed out")
        assert hassh_server("10.0.0.1", 22, timeout=1.0) is None
