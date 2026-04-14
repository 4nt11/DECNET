#!/usr/bin/env python3
"""
DECNET passive TLS sniffer.

Captures TLS handshakes on the MACVLAN interface (shared network namespace
with the decky base container). Extracts JA3/JA3S fingerprints and connection
metadata, then emits structured RFC 5424 log lines to stdout for the
host-side collector to ingest.

Requires: NET_RAW + NET_ADMIN capabilities (set in compose fragment).

JA3  — MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)
JA3S — MD5(SSLVersion,Cipher,Extensions)

GREASE values (RFC 8701) are excluded from all lists before hashing.
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sniff

from decnet_logging import SEVERITY_INFO, SEVERITY_WARNING, syslog_line, write_syslog_file

# ─── Configuration ────────────────────────────────────────────────────────────

NODE_NAME: str = os.environ.get("NODE_NAME", "decky-sniffer")
SERVICE_NAME: str = "sniffer"

# Session TTL in seconds — drop half-open sessions after this
_SESSION_TTL: float = 60.0

# GREASE values per RFC 8701 — 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA
_GREASE: frozenset[int] = frozenset(0x0A0A + i * 0x1010 for i in range(16))

# TLS record / handshake type constants
_TLS_RECORD_HANDSHAKE: int = 0x16
_TLS_HT_CLIENT_HELLO: int = 0x01
_TLS_HT_SERVER_HELLO: int = 0x02

# TLS extension types we extract for metadata
_EXT_SNI: int = 0x0000
_EXT_SUPPORTED_GROUPS: int = 0x000A
_EXT_EC_POINT_FORMATS: int = 0x000B
_EXT_ALPN: int = 0x0010
_EXT_SESSION_TICKET: int = 0x0023

# ─── Session tracking ─────────────────────────────────────────────────────────

# Key: (src_ip, src_port, dst_ip, dst_port) — forward 4-tuple from ClientHello
# Value: parsed ClientHello metadata dict
_sessions: dict[tuple[str, int, str, int], dict[str, Any]] = {}
_session_ts: dict[tuple[str, int, str, int], float] = {}


# ─── GREASE helpers ───────────────────────────────────────────────────────────

def _is_grease(value: int) -> bool:
    return value in _GREASE


def _filter_grease(values: list[int]) -> list[int]:
    return [v for v in values if not _is_grease(v)]


# ─── Pure-Python TLS record parser ────────────────────────────────────────────

def _parse_client_hello(data: bytes) -> dict[str, Any] | None:
    """
    Parse a TLS ClientHello from raw bytes (starting at TLS record header).
    Returns a dict of parsed fields, or None if not a valid ClientHello.
    """
    try:
        if len(data) < 6:
            return None
        # TLS record header: content_type(1) version(2) length(2)
        if data[0] != _TLS_RECORD_HANDSHAKE:
            return None
        record_len = struct.unpack_from("!H", data, 3)[0]
        if len(data) < 5 + record_len:
            return None

        # Handshake header: type(1) length(3)
        hs = data[5:]
        if hs[0] != _TLS_HT_CLIENT_HELLO:
            return None

        hs_len = struct.unpack_from("!I", b"\x00" + hs[1:4])[0]
        body = hs[4: 4 + hs_len]
        if len(body) < 34:
            return None

        pos = 0
        # ClientHello version (2 bytes) — used for JA3
        tls_version = struct.unpack_from("!H", body, pos)[0]
        pos += 2

        # Random (32 bytes)
        pos += 32

        # Session ID
        session_id_len = body[pos]
        pos += 1 + session_id_len

        # Cipher Suites
        cs_len = struct.unpack_from("!H", body, pos)[0]
        pos += 2
        cipher_suites = [
            struct.unpack_from("!H", body, pos + i * 2)[0]
            for i in range(cs_len // 2)
        ]
        pos += cs_len

        # Compression Methods
        comp_len = body[pos]
        pos += 1 + comp_len

        # Extensions
        extensions: list[int] = []
        supported_groups: list[int] = []
        ec_point_formats: list[int] = []
        sni: str = ""
        alpn: list[str] = []

        if pos + 2 <= len(body):
            ext_total = struct.unpack_from("!H", body, pos)[0]
            pos += 2
            ext_end = pos + ext_total

            while pos + 4 <= ext_end:
                ext_type = struct.unpack_from("!H", body, pos)[0]
                ext_len = struct.unpack_from("!H", body, pos + 2)[0]
                ext_data = body[pos + 4: pos + 4 + ext_len]
                pos += 4 + ext_len

                if not _is_grease(ext_type):
                    extensions.append(ext_type)

                if ext_type == _EXT_SNI and len(ext_data) > 5:
                    # server_name_list_length(2) type(1) name_length(2) name
                    sni = ext_data[5:].decode("ascii", errors="replace")

                elif ext_type == _EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
                    grp_len = struct.unpack_from("!H", ext_data, 0)[0]
                    supported_groups = [
                        struct.unpack_from("!H", ext_data, 2 + i * 2)[0]
                        for i in range(grp_len // 2)
                    ]

                elif ext_type == _EXT_EC_POINT_FORMATS and len(ext_data) >= 1:
                    pf_len = ext_data[0]
                    ec_point_formats = list(ext_data[1: 1 + pf_len])

                elif ext_type == _EXT_ALPN and len(ext_data) >= 2:
                    proto_list_len = struct.unpack_from("!H", ext_data, 0)[0]
                    ap = 2
                    while ap < 2 + proto_list_len:
                        plen = ext_data[ap]
                        alpn.append(ext_data[ap + 1: ap + 1 + plen].decode("ascii", errors="replace"))
                        ap += 1 + plen

        filtered_ciphers = _filter_grease(cipher_suites)
        filtered_groups = _filter_grease(supported_groups)

        return {
            "tls_version": tls_version,
            "cipher_suites": filtered_ciphers,
            "extensions": extensions,
            "supported_groups": filtered_groups,
            "ec_point_formats": ec_point_formats,
            "sni": sni,
            "alpn": alpn,
        }

    except Exception:
        return None


def _parse_server_hello(data: bytes) -> dict[str, Any] | None:
    """
    Parse a TLS ServerHello from raw bytes.
    Returns dict with tls_version, cipher_suite, extensions, or None.
    """
    try:
        if len(data) < 6 or data[0] != _TLS_RECORD_HANDSHAKE:
            return None

        hs = data[5:]
        if hs[0] != _TLS_HT_SERVER_HELLO:
            return None

        hs_len = struct.unpack_from("!I", b"\x00" + hs[1:4])[0]
        body = hs[4: 4 + hs_len]
        if len(body) < 35:
            return None

        pos = 0
        tls_version = struct.unpack_from("!H", body, pos)[0]
        pos += 2

        # Random (32 bytes)
        pos += 32

        # Session ID
        session_id_len = body[pos]
        pos += 1 + session_id_len

        if pos + 2 > len(body):
            return None

        cipher_suite = struct.unpack_from("!H", body, pos)[0]
        pos += 2

        # Compression method (1 byte)
        pos += 1

        extensions: list[int] = []
        if pos + 2 <= len(body):
            ext_total = struct.unpack_from("!H", body, pos)[0]
            pos += 2
            ext_end = pos + ext_total
            while pos + 4 <= ext_end:
                ext_type = struct.unpack_from("!H", body, pos)[0]
                ext_len = struct.unpack_from("!H", body, pos + 2)[0]
                pos += 4 + ext_len
                if not _is_grease(ext_type):
                    extensions.append(ext_type)

        return {
            "tls_version": tls_version,
            "cipher_suite": cipher_suite,
            "extensions": extensions,
        }

    except Exception:
        return None


# ─── JA3 / JA3S computation ───────────────────────────────────────────────────

def _tls_version_str(version: int) -> str:
    return {
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
        0x0200: "SSL 2.0",
        0x0300: "SSL 3.0",
    }.get(version, f"0x{version:04x}")


def _ja3(ch: dict[str, Any]) -> tuple[str, str]:
    """Return (ja3_string, ja3_hash) for a parsed ClientHello."""
    parts = [
        str(ch["tls_version"]),
        "-".join(str(c) for c in ch["cipher_suites"]),
        "-".join(str(e) for e in ch["extensions"]),
        "-".join(str(g) for g in ch["supported_groups"]),
        "-".join(str(p) for p in ch["ec_point_formats"]),
    ]
    ja3_str = ",".join(parts)
    return ja3_str, hashlib.md5(ja3_str.encode()).hexdigest()


def _ja3s(sh: dict[str, Any]) -> tuple[str, str]:
    """Return (ja3s_string, ja3s_hash) for a parsed ServerHello."""
    parts = [
        str(sh["tls_version"]),
        str(sh["cipher_suite"]),
        "-".join(str(e) for e in sh["extensions"]),
    ]
    ja3s_str = ",".join(parts)
    return ja3s_str, hashlib.md5(ja3s_str.encode()).hexdigest()


# ─── Session cleanup ─────────────────────────────────────────────────────────

def _cleanup_sessions() -> None:
    now = time.monotonic()
    stale = [k for k, ts in _session_ts.items() if now - ts > _SESSION_TTL]
    for k in stale:
        _sessions.pop(k, None)
        _session_ts.pop(k, None)


# ─── Logging helpers ─────────────────────────────────────────────────────────

def _log(event_type: str, severity: int = SEVERITY_INFO, **fields: Any) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity=severity, **fields)
    write_syslog_file(line)


# ─── Packet callback ─────────────────────────────────────────────────────────

def _on_packet(pkt: Any) -> None:
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    payload = bytes(tcp.payload)
    if not payload:
        return

    src_ip: str = ip.src
    dst_ip: str = ip.dst
    src_port: int = tcp.sport
    dst_port: int = tcp.dport

    # TLS record check
    if payload[0] != _TLS_RECORD_HANDSHAKE:
        return

    # Attempt ClientHello parse
    ch = _parse_client_hello(payload)
    if ch is not None:
        _cleanup_sessions()

        key = (src_ip, src_port, dst_ip, dst_port)
        ja3_str, ja3_hash = _ja3(ch)

        _sessions[key] = {
            "ja3": ja3_hash,
            "ja3_str": ja3_str,
            "tls_version": ch["tls_version"],
            "cipher_suites": ch["cipher_suites"],
            "extensions": ch["extensions"],
            "sni": ch["sni"],
            "alpn": ch["alpn"],
        }
        _session_ts[key] = time.monotonic()

        _log(
            "tls_client_hello",
            src_ip=src_ip,
            src_port=str(src_port),
            dst_ip=dst_ip,
            dst_port=str(dst_port),
            ja3=ja3_hash,
            tls_version=_tls_version_str(ch["tls_version"]),
            sni=ch["sni"] or "",
            alpn=",".join(ch["alpn"]),
            raw_ciphers="-".join(str(c) for c in ch["cipher_suites"]),
            raw_extensions="-".join(str(e) for e in ch["extensions"]),
        )
        return

    # Attempt ServerHello parse
    sh = _parse_server_hello(payload)
    if sh is not None:
        # Reverse 4-tuple to find the matching ClientHello
        rev_key = (dst_ip, dst_port, src_ip, src_port)
        ch_data = _sessions.pop(rev_key, None)
        _session_ts.pop(rev_key, None)

        ja3s_str, ja3s_hash = _ja3s(sh)

        fields: dict[str, Any] = {
            "src_ip": dst_ip,   # original attacker is now the destination
            "src_port": str(dst_port),
            "dst_ip": src_ip,
            "dst_port": str(src_port),
            "ja3s": ja3s_hash,
            "tls_version": _tls_version_str(sh["tls_version"]),
        }

        if ch_data:
            fields["ja3"] = ch_data["ja3"]
            fields["sni"] = ch_data["sni"] or ""
            fields["alpn"] = ",".join(ch_data["alpn"])
            fields["raw_ciphers"] = "-".join(str(c) for c in ch_data["cipher_suites"])
            fields["raw_extensions"] = "-".join(str(e) for e in ch_data["extensions"])

        _log("tls_session", severity=SEVERITY_WARNING, **fields)


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _log("startup", msg=f"sniffer started node={NODE_NAME}")
    sniff(
        filter="tcp",
        prn=_on_packet,
        store=False,
    )
