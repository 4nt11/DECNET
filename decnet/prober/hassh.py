"""
HASSHServer — SSH server fingerprinting via KEX_INIT algorithm ordering.

Connects to an SSH server, completes the version exchange, captures the
server's SSH_MSG_KEXINIT message, and hashes the server-to-client algorithm
fields (kex, encryption, MAC, compression) into a 32-character MD5 digest.

This is the *server* variant of HASSH (HASSHServer). It fingerprints what
the server *offers*, which identifies the SSH implementation (OpenSSH,
Paramiko, libssh, Cobalt Strike SSH, etc.).

Stdlib only (socket, struct, hashlib). No DECNET imports.
"""

from __future__ import annotations

import hashlib
import socket
import struct
from typing import Any

# SSH protocol constants
_SSH_MSG_KEXINIT = 20
_KEX_INIT_COOKIE_LEN = 16
_KEX_INIT_NAME_LISTS = 10  # 10 name-list fields in KEX_INIT

# Blend in as a normal OpenSSH client
_CLIENT_BANNER = b"SSH-2.0-OpenSSH_9.6\r\n"

# Max bytes to read for server banner
_MAX_BANNER_LEN = 256

# Max bytes for a single SSH packet (KEX_INIT is typically < 2KB)
_MAX_PACKET_LEN = 35000


# ─── SSH connection + KEX_INIT capture ──────────────────────────────────────

def _ssh_connect(
    host: str,
    port: int,
    timeout: float,
) -> tuple[str, bytes] | None:
    """
    TCP connect, exchange version strings, read server's KEX_INIT.

    Returns (server_banner, kex_init_payload) or None on failure.
    The kex_init_payload starts at the SSH_MSG_KEXINIT type byte.
    """
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        # 1. Read server banner (line ending \r\n or \n)
        banner = _read_banner(sock)
        if banner is None or not banner.startswith("SSH-"):
            return None

        # 2. Send our client version string
        sock.sendall(_CLIENT_BANNER)

        # 3. Read the server's first binary packet (should be KEX_INIT)
        payload = _read_ssh_packet(sock)
        if payload is None or len(payload) < 1:
            return None

        if payload[0] != _SSH_MSG_KEXINIT:
            return None

        return (banner, payload)

    except (OSError, socket.timeout, TimeoutError, ConnectionError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _read_banner(sock: socket.socket) -> str | None:
    """Read the SSH version banner line from the socket."""
    buf = b""
    while len(buf) < _MAX_BANNER_LEN:
        try:
            byte = sock.recv(1)
        except (OSError, socket.timeout, TimeoutError):
            return None
        if not byte:
            return None
        buf += byte
        if buf.endswith(b"\n"):
            break

    try:
        return buf.decode("utf-8", errors="replace").rstrip("\r\n")
    except Exception:
        return None


def _read_ssh_packet(sock: socket.socket) -> bytes | None:
    """
    Read a single SSH binary packet and return its payload.

    SSH binary packet format:
        uint32  packet_length   (not including itself or MAC)
        byte    padding_length
        byte[]  payload         (packet_length - padding_length - 1)
        byte[]  padding
    """
    header = _recv_exact(sock, 4)
    if header is None:
        return None

    packet_length = struct.unpack("!I", header)[0]
    if packet_length < 2 or packet_length > _MAX_PACKET_LEN:
        return None

    rest = _recv_exact(sock, packet_length)
    if rest is None:
        return None

    padding_length = rest[0]
    payload_length = packet_length - padding_length - 1
    if payload_length < 1 or payload_length > len(rest) - 1:
        return None

    return rest[1 : 1 + payload_length]


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes from socket, or None on failure."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (OSError, socket.timeout, TimeoutError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


# ─── KEX_INIT parsing ──────────────────────────────────────────────────────

def _parse_kex_init(payload: bytes) -> dict[str, str] | None:
    """
    Parse SSH_MSG_KEXINIT payload and extract the 10 name-list fields.

    Payload layout:
        byte    SSH_MSG_KEXINIT (20)
        byte[16] cookie
        10 × name-list:
            uint32  length
            byte[]  utf-8 string (comma-separated algorithm names)
        bool    first_kex_packet_follows
        uint32  reserved

    Returns dict with keys: kex_algorithms, server_host_key_algorithms,
    encryption_client_to_server, encryption_server_to_client,
    mac_client_to_server, mac_server_to_client,
    compression_client_to_server, compression_server_to_client,
    languages_client_to_server, languages_server_to_client.
    """
    if len(payload) < 1 + _KEX_INIT_COOKIE_LEN + 4:
        return None

    offset = 1 + _KEX_INIT_COOKIE_LEN  # skip type byte + cookie

    field_names = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_client_to_server",
        "encryption_server_to_client",
        "mac_client_to_server",
        "mac_server_to_client",
        "compression_client_to_server",
        "compression_server_to_client",
        "languages_client_to_server",
        "languages_server_to_client",
    ]

    fields: dict[str, str] = {}
    for name in field_names:
        if offset + 4 > len(payload):
            return None
        length = struct.unpack("!I", payload[offset : offset + 4])[0]
        offset += 4
        if offset + length > len(payload):
            return None
        fields[name] = payload[offset : offset + length].decode(
            "utf-8", errors="replace"
        )
        offset += length

    return fields


# ─── HASSH computation ──────────────────────────────────────────────────────

def _compute_hassh(kex: str, enc: str, mac: str, comp: str) -> str:
    """
    Compute HASSHServer hash: MD5 of "kex;enc_s2c;mac_s2c;comp_s2c".

    Returns 32-character lowercase hex digest.
    """
    raw = f"{kex};{enc};{mac};{comp}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest()  # nosec B324


# ─── Public API ─────────────────────────────────────────────────────────────

def hassh_server(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    """
    Connect to an SSH server and compute its HASSHServer fingerprint.

    Returns a dict with the hash, banner, and raw algorithm fields,
    or None if the host is not running an SSH server on the given port.
    """
    result = _ssh_connect(host, port, timeout)
    if result is None:
        return None

    banner, payload = result
    fields = _parse_kex_init(payload)
    if fields is None:
        return None

    kex = fields["kex_algorithms"]
    enc = fields["encryption_server_to_client"]
    mac = fields["mac_server_to_client"]
    comp = fields["compression_server_to_client"]

    return {
        "hassh_server": _compute_hassh(kex, enc, mac, comp),
        "banner": banner,
        "kex_algorithms": kex,
        "encryption_s2c": enc,
        "mac_s2c": mac,
        "compression_s2c": comp,
    }
