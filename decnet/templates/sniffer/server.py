#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
syslog-relay passive TLS sniffer.

Captures TLS handshakes on the MACVLAN interface (shared network namespace
with the decky base container). Extracts fingerprints and connection
metadata, then emits structured RFC 5424 log lines to stdout for the
host-side collector to ingest.

Requires: NET_RAW + NET_ADMIN capabilities (set in compose fragment).

Supported fingerprints:
  JA3  — MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)
  JA3S — MD5(SSLVersion,Cipher,Extensions)
  JA4  — {proto}{ver}{sni}{#cs}{#ext}{alpn}_{sha256_12(sorted_cs)}_{sha256_12(sorted_ext,sigalgs)}
  JA4S — {proto}{ver}{#ext}{alpn}_{sha256_12(cipher,sorted_ext)}
  JA4L — TCP RTT latency measurement (client_ttl, server_rtt_ms)
  TLS session resumption detection (session tickets, PSK, 0-RTT)
  Certificate extraction (TLS ≤1.2 only — 1.3 encrypts certs)

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

from syslog_bridge import SEVERITY_INFO, SEVERITY_WARNING, syslog_line, write_syslog_file

# ─── Configuration ────────────────────────────────────────────────────────────

NODE_NAME: str = os.environ.get("NODE_NAME", "decky-sniffer")
SERVICE_NAME: str = "sniffer"

# Session TTL in seconds — drop half-open sessions after this
_SESSION_TTL: float = 60.0

# Dedup TTL — suppress identical fingerprint events from the same source IP
# within this window (seconds). Set to 0 to disable dedup.
_DEDUP_TTL: float = float(os.environ.get("DEDUP_TTL", "300"))

# GREASE values per RFC 8701 — 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA
_GREASE: frozenset[int] = frozenset(0x0A0A + i * 0x1010 for i in range(16))

# TLS record / handshake type constants
_TLS_RECORD_HANDSHAKE: int = 0x16
_TLS_HT_CLIENT_HELLO: int = 0x01
_TLS_HT_SERVER_HELLO: int = 0x02
_TLS_HT_CERTIFICATE: int = 0x0B

# TLS extension types we extract for metadata
_EXT_SNI: int = 0x0000
_EXT_SUPPORTED_GROUPS: int = 0x000A
_EXT_EC_POINT_FORMATS: int = 0x000B
_EXT_SIGNATURE_ALGORITHMS: int = 0x000D
_EXT_ALPN: int = 0x0010
_EXT_SESSION_TICKET: int = 0x0023
_EXT_SUPPORTED_VERSIONS: int = 0x002B
_EXT_PRE_SHARED_KEY: int = 0x0029
_EXT_EARLY_DATA: int = 0x002A

# TCP flags
_TCP_SYN: int = 0x02
_TCP_ACK: int = 0x10

# ─── Session tracking ─────────────────────────────────────────────────────────

# Key: (src_ip, src_port, dst_ip, dst_port) — forward 4-tuple from ClientHello
# Value: parsed ClientHello metadata dict
_sessions: dict[tuple[str, int, str, int], dict[str, Any]] = {}
_session_ts: dict[tuple[str, int, str, int], float] = {}

# TCP RTT tracking for JA4L: key = (client_ip, client_port, server_ip, server_port)
# Value: {"syn_time": float, "ttl": int}
_tcp_syn: dict[tuple[str, int, str, int], dict[str, Any]] = {}
# Completed RTT measurements: key = same 4-tuple, value = {"rtt_ms": float, "client_ttl": int}
_tcp_rtt: dict[tuple[str, int, str, int], dict[str, Any]] = {}


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
        session_id = body[pos + 1: pos + 1 + session_id_len]
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
        signature_algorithms: list[int] = []
        supported_versions: list[int] = []
        sni: str = ""
        alpn: list[str] = []
        has_session_ticket_data: bool = False
        has_pre_shared_key: bool = False
        has_early_data: bool = False

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

                elif ext_type == _EXT_SIGNATURE_ALGORITHMS and len(ext_data) >= 2:
                    sa_len = struct.unpack_from("!H", ext_data, 0)[0]
                    signature_algorithms = [
                        struct.unpack_from("!H", ext_data, 2 + i * 2)[0]
                        for i in range(sa_len // 2)
                    ]

                elif ext_type == _EXT_SUPPORTED_VERSIONS and len(ext_data) >= 1:
                    sv_len = ext_data[0]
                    supported_versions = [
                        struct.unpack_from("!H", ext_data, 1 + i * 2)[0]
                        for i in range(sv_len // 2)
                    ]

                elif ext_type == _EXT_SESSION_TICKET:
                    has_session_ticket_data = len(ext_data) > 0

                elif ext_type == _EXT_PRE_SHARED_KEY:
                    has_pre_shared_key = True

                elif ext_type == _EXT_EARLY_DATA:
                    has_early_data = True

        filtered_ciphers = _filter_grease(cipher_suites)
        filtered_groups = _filter_grease(supported_groups)
        filtered_sig_algs = _filter_grease(signature_algorithms)
        filtered_versions = _filter_grease(supported_versions)

        return {
            "tls_version": tls_version,
            "cipher_suites": filtered_ciphers,
            "extensions": extensions,
            "supported_groups": filtered_groups,
            "ec_point_formats": ec_point_formats,
            "signature_algorithms": filtered_sig_algs,
            "supported_versions": filtered_versions,
            "sni": sni,
            "alpn": alpn,
            "session_id": session_id,
            "has_session_ticket_data": has_session_ticket_data,
            "has_pre_shared_key": has_pre_shared_key,
            "has_early_data": has_early_data,
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
        selected_version: int | None = None
        alpn: str = ""

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

                if ext_type == _EXT_SUPPORTED_VERSIONS and len(ext_data) >= 2:
                    selected_version = struct.unpack_from("!H", ext_data, 0)[0]

                elif ext_type == _EXT_ALPN and len(ext_data) >= 2:
                    proto_list_len = struct.unpack_from("!H", ext_data, 0)[0]
                    if proto_list_len > 0 and len(ext_data) >= 4:
                        plen = ext_data[2]
                        alpn = ext_data[3: 3 + plen].decode("ascii", errors="replace")

        return {
            "tls_version": tls_version,
            "cipher_suite": cipher_suite,
            "extensions": extensions,
            "selected_version": selected_version,
            "alpn": alpn,
        }

    except Exception:
        return None


def _parse_certificate(data: bytes) -> dict[str, Any] | None:
    """
    Parse a TLS Certificate handshake message from raw bytes.

    Only works for TLS 1.2 and below — TLS 1.3 encrypts the Certificate
    message. Extracts basic details from the first (leaf) certificate
    using minimal DER/ASN.1 parsing.
    """
    try:
        if len(data) < 6 or data[0] != _TLS_RECORD_HANDSHAKE:
            return None

        hs = data[5:]
        if hs[0] != _TLS_HT_CERTIFICATE:
            return None

        hs_len = struct.unpack_from("!I", b"\x00" + hs[1:4])[0]
        body = hs[4: 4 + hs_len]
        if len(body) < 3:
            return None

        # Certificate list total length (3 bytes)
        certs_len = struct.unpack_from("!I", b"\x00" + body[0:3])[0]
        if certs_len == 0:
            return None

        pos = 3
        # First certificate length (3 bytes)
        if pos + 3 > len(body):
            return None
        cert_len = struct.unpack_from("!I", b"\x00" + body[pos:pos + 3])[0]
        pos += 3
        if pos + cert_len > len(body):
            return None

        cert_der = body[pos: pos + cert_len]
        return _parse_x509_der(cert_der)

    except Exception:
        return None


# ─── Minimal DER/ASN.1 X.509 parser ─────────────────────────────────────────

def _der_read_tag_len(data: bytes, pos: int) -> tuple[int, int, int]:
    """Read a DER tag and length. Returns (tag, content_start, content_length)."""
    tag = data[pos]
    pos += 1
    length_byte = data[pos]
    pos += 1
    if length_byte & 0x80:
        num_bytes = length_byte & 0x7F
        length = int.from_bytes(data[pos: pos + num_bytes], "big")
        pos += num_bytes
    else:
        length = length_byte
    return tag, pos, length


def _der_read_sequence(data: bytes, pos: int) -> tuple[int, int]:
    """Read a SEQUENCE tag, return (content_start, content_length)."""
    tag, content_start, length = _der_read_tag_len(data, pos)
    return content_start, length


def _der_read_oid(data: bytes, pos: int, length: int) -> str:
    """Decode a DER OID to dotted string."""
    if length < 1:
        return ""
    first = data[pos]
    oid_parts = [str(first // 40), str(first % 40)]
    val = 0
    for i in range(1, length):
        b = data[pos + i]
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            oid_parts.append(str(val))
            val = 0
    return ".".join(oid_parts)


def _der_extract_cn(data: bytes, start: int, length: int) -> str:
    """Walk an X.501 Name (SEQUENCE of SETs of SEQUENCE of OID+value) to find CN."""
    pos = start
    end = start + length
    while pos < end:
        # Each RDN is a SET
        set_tag, set_start, set_len = _der_read_tag_len(data, pos)
        if set_tag != 0x31:  # SET
            break
        set_end = set_start + set_len

        # Inside the SET, each attribute is a SEQUENCE
        attr_pos = set_start
        while attr_pos < set_end:
            seq_tag, seq_start, seq_len = _der_read_tag_len(data, attr_pos)
            if seq_tag != 0x30:  # SEQUENCE
                break
            # OID
            oid_tag, oid_start, oid_len = _der_read_tag_len(data, seq_start)
            if oid_tag == 0x06:
                oid = _der_read_oid(data, oid_start, oid_len)
                # CN OID = 2.5.4.3
                if oid == "2.5.4.3":
                    val_tag, val_start, val_len = _der_read_tag_len(data, oid_start + oid_len)
                    return data[val_start: val_start + val_len].decode("utf-8", errors="replace")
            attr_pos = seq_start + seq_len

        pos = set_end
    return ""


def _der_extract_name_str(data: bytes, start: int, length: int) -> str:
    """Extract a human-readable summary of an X.501 Name (all RDN values joined)."""
    parts: list[str] = []
    pos = start
    end = start + length
    oid_names = {
        "2.5.4.3": "CN",
        "2.5.4.6": "C",
        "2.5.4.7": "L",
        "2.5.4.8": "ST",
        "2.5.4.10": "O",
        "2.5.4.11": "OU",
    }
    while pos < end:
        set_tag, set_start, set_len = _der_read_tag_len(data, pos)
        if set_tag != 0x31:
            break
        set_end = set_start + set_len
        attr_pos = set_start
        while attr_pos < set_end:
            seq_tag, seq_start, seq_len = _der_read_tag_len(data, attr_pos)
            if seq_tag != 0x30:
                break
            oid_tag, oid_start, oid_len = _der_read_tag_len(data, seq_start)
            if oid_tag == 0x06:
                oid = _der_read_oid(data, oid_start, oid_len)
                val_tag, val_start, val_len = _der_read_tag_len(data, oid_start + oid_len)
                val = data[val_start: val_start + val_len].decode("utf-8", errors="replace")
                name = oid_names.get(oid, oid)
                parts.append(f"{name}={val}")
            attr_pos = seq_start + seq_len
        pos = set_end
    return ", ".join(parts)


def _parse_x509_der(cert_der: bytes) -> dict[str, Any] | None:
    """
    Minimal X.509 DER parser. Extracts subject CN, issuer string,
    validity period, and self-signed flag.

    Structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    tbsCertificate: SEQUENCE {
        version [0] EXPLICIT, serialNumber, signature,
        issuer, validity { notBefore, notAfter },
        subject, subjectPublicKeyInfo, ...extensions
    }
    """
    try:
        # Outer SEQUENCE
        outer_start, outer_len = _der_read_sequence(cert_der, 0)
        # tbsCertificate SEQUENCE
        tbs_tag, tbs_start, tbs_len = _der_read_tag_len(cert_der, outer_start)
        tbs_end = tbs_start + tbs_len
        pos = tbs_start

        # version [0] EXPLICIT — optional, skip if present
        if cert_der[pos] == 0xA0:
            _, v_start, v_len = _der_read_tag_len(cert_der, pos)
            pos = v_start + v_len

        # serialNumber (INTEGER)
        _, sn_start, sn_len = _der_read_tag_len(cert_der, pos)
        pos = sn_start + sn_len

        # signature algorithm (SEQUENCE)
        _, sa_start, sa_len = _der_read_tag_len(cert_der, pos)
        pos = sa_start + sa_len

        # issuer (SEQUENCE)
        issuer_tag, issuer_start, issuer_len = _der_read_tag_len(cert_der, pos)
        issuer_str = _der_extract_name_str(cert_der, issuer_start, issuer_len)
        issuer_cn = _der_extract_cn(cert_der, issuer_start, issuer_len)
        pos = issuer_start + issuer_len

        # validity (SEQUENCE of two times)
        val_tag, val_start, val_len = _der_read_tag_len(cert_der, pos)
        # notBefore
        nb_tag, nb_start, nb_len = _der_read_tag_len(cert_der, val_start)
        not_before = cert_der[nb_start: nb_start + nb_len].decode("ascii", errors="replace")
        # notAfter
        na_tag, na_start, na_len = _der_read_tag_len(cert_der, nb_start + nb_len)
        not_after = cert_der[na_start: na_start + na_len].decode("ascii", errors="replace")
        pos = val_start + val_len

        # subject (SEQUENCE)
        subj_tag, subj_start, subj_len = _der_read_tag_len(cert_der, pos)
        subject_cn = _der_extract_cn(cert_der, subj_start, subj_len)
        subject_str = _der_extract_name_str(cert_der, subj_start, subj_len)

        # Self-signed: issuer CN matches subject CN (basic check)
        self_signed = (issuer_cn == subject_cn) and subject_cn != ""

        # SANs are in extensions — attempt to find them
        pos = subj_start + subj_len
        sans: list[str] = _extract_sans(cert_der, pos, tbs_end)

        return {
            "subject_cn": subject_cn,
            "subject": subject_str,
            "issuer": issuer_str,
            "issuer_cn": issuer_cn,
            "not_before": not_before,
            "not_after": not_after,
            "self_signed": self_signed,
            "sans": sans,
        }

    except Exception:
        return None


def _extract_sans(cert_der: bytes, pos: int, end: int) -> list[str]:
    """
    Attempt to extract Subject Alternative Names from X.509v3 extensions.
    SAN OID = 2.5.29.17
    """
    sans: list[str] = []
    try:
        # Skip subjectPublicKeyInfo SEQUENCE
        if pos >= end:
            return sans
        spki_tag, spki_start, spki_len = _der_read_tag_len(cert_der, pos)
        pos = spki_start + spki_len

        # Extensions are wrapped in [3] EXPLICIT
        while pos < end:
            tag = cert_der[pos]
            if tag == 0xA3:  # [3] EXPLICIT — extensions wrapper
                _, ext_wrap_start, ext_wrap_len = _der_read_tag_len(cert_der, pos)
                # Inner SEQUENCE of extensions
                _, exts_start, exts_len = _der_read_tag_len(cert_der, ext_wrap_start)
                epos = exts_start
                eend = exts_start + exts_len
                while epos < eend:
                    # Each extension is a SEQUENCE { OID, [critical], value }
                    ext_tag, ext_start, ext_len = _der_read_tag_len(cert_der, epos)
                    ext_end = ext_start + ext_len

                    oid_tag, oid_start, oid_len = _der_read_tag_len(cert_der, ext_start)
                    if oid_tag == 0x06:
                        oid = _der_read_oid(cert_der, oid_start, oid_len)
                        if oid == "2.5.29.17":  # SAN
                            # Find the OCTET STRING containing the SAN value
                            vpos = oid_start + oid_len
                            # Skip optional BOOLEAN (critical)
                            if vpos < ext_end and cert_der[vpos] == 0x01:
                                _, bs, bl = _der_read_tag_len(cert_der, vpos)
                                vpos = bs + bl
                            # OCTET STRING wrapping the SAN SEQUENCE
                            if vpos < ext_end:
                                os_tag, os_start, os_len = _der_read_tag_len(cert_der, vpos)
                                if os_tag == 0x04:
                                    sans = _parse_san_sequence(cert_der, os_start, os_len)
                    epos = ext_end
                break
            else:
                _, skip_start, skip_len = _der_read_tag_len(cert_der, pos)
                pos = skip_start + skip_len
    except Exception:
        pass
    return sans


def _parse_san_sequence(data: bytes, start: int, length: int) -> list[str]:
    """Parse a GeneralNames SEQUENCE to extract DNS names and IPs."""
    names: list[str] = []
    try:
        # The SAN value is itself a SEQUENCE of GeneralName
        seq_tag, seq_start, seq_len = _der_read_tag_len(data, start)
        pos = seq_start
        end = seq_start + seq_len
        while pos < end:
            tag = data[pos]
            _, val_start, val_len = _der_read_tag_len(data, pos)
            context_tag = tag & 0x1F
            if context_tag == 2:  # dNSName
                names.append(data[val_start: val_start + val_len].decode("ascii", errors="replace"))
            elif context_tag == 7 and val_len == 4:  # iPAddress (IPv4)
                names.append(".".join(str(b) for b in data[val_start: val_start + val_len]))
            pos = val_start + val_len
    except Exception:
        pass
    return names


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
    # JA3 fingerprint spec uses MD5; not security-relevant.
    return ja3_str, hashlib.md5(ja3_str.encode(), usedforsecurity=False).hexdigest()


def _ja3s(sh: dict[str, Any]) -> tuple[str, str]:
    """Return (ja3s_string, ja3s_hash) for a parsed ServerHello."""
    parts = [
        str(sh["tls_version"]),
        str(sh["cipher_suite"]),
        "-".join(str(e) for e in sh["extensions"]),
    ]
    ja3s_str = ",".join(parts)
    # JA3S fingerprint spec uses MD5; not security-relevant.
    return ja3s_str, hashlib.md5(ja3s_str.encode(), usedforsecurity=False).hexdigest()


# ─── JA4 / JA4S computation ──────────────────────────────────────────────────

def _ja4_version(ch: dict[str, Any]) -> str:
    """
    Determine JA4 TLS version string (2 chars).
    Uses supported_versions extension if present (TLS 1.3 advertises 0x0303 in
    ClientHello.version but 0x0304 in supported_versions).
    """
    versions = ch.get("supported_versions", [])
    if versions:
        best = max(versions)
    else:
        best = ch["tls_version"]
    return {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
        0x0200: "s2",
    }.get(best, "00")


def _ja4_alpn_tag(alpn_list: list[str] | str) -> str:
    """
    JA4 ALPN tag: first and last character of the first ALPN protocol.
    No ALPN → "00".
    """
    if isinstance(alpn_list, str):
        proto = alpn_list
    elif alpn_list:
        proto = alpn_list[0]
    else:
        return "00"

    if not proto:
        return "00"
    if len(proto) == 1:
        return proto[0] + proto[0]
    return proto[0] + proto[-1]


def _sha256_12(text: str) -> str:
    """First 12 hex chars of SHA-256."""
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def _ja4(ch: dict[str, Any]) -> str:
    """
    Compute JA4 fingerprint from a parsed ClientHello.

    Format: a_b_c where
      a = {t|q}{version:2}{d|i}{cipher_count:02d}{ext_count:02d}{alpn_tag:2}
      b = sha256_12(sorted_cipher_suites, comma-separated)
      c = sha256_12(sorted_extensions,sorted_signature_algorithms)

    Protocol is always 't' (TCP) since we capture on a TCP socket.
    SNI present → 'd' (domain), absent → 'i' (IP).
    """
    proto = "t"
    ver = _ja4_version(ch)
    sni_flag = "d" if ch.get("sni") else "i"

    # Counts — GREASE already filtered, but also exclude SNI (0x0000) and ALPN (0x0010)
    # from extension count per JA4 spec? No — JA4 counts all non-GREASE extensions.
    cs_count = min(len(ch["cipher_suites"]), 99)
    ext_count = min(len(ch["extensions"]), 99)
    alpn_tag = _ja4_alpn_tag(ch.get("alpn", []))

    section_a = f"{proto}{ver}{sni_flag}{cs_count:02d}{ext_count:02d}{alpn_tag}"

    # Section b: sorted cipher suites as decimal, comma-separated
    sorted_cs = sorted(ch["cipher_suites"])
    section_b = _sha256_12(",".join(str(c) for c in sorted_cs))

    # Section c: sorted extensions + sorted signature algorithms
    sorted_ext = sorted(ch["extensions"])
    sorted_sa = sorted(ch.get("signature_algorithms", []))
    ext_str = ",".join(str(e) for e in sorted_ext)
    sa_str = ",".join(str(s) for s in sorted_sa)
    combined = f"{ext_str}_{sa_str}" if sa_str else ext_str
    section_c = _sha256_12(combined)

    return f"{section_a}_{section_b}_{section_c}"


def _ja4s(sh: dict[str, Any]) -> str:
    """
    Compute JA4S fingerprint from a parsed ServerHello.

    Format: a_b where
      a = {t|q}{version:2}{ext_count:02d}{alpn_tag:2}
      b = sha256_12({cipher_suite},{sorted_extensions comma-separated})
    """
    proto = "t"
    # Use selected_version from supported_versions ext if available
    selected = sh.get("selected_version")
    if selected:
        ver = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
               0x0300: "s3", 0x0200: "s2"}.get(selected, "00")
    else:
        ver = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
               0x0300: "s3", 0x0200: "s2"}.get(sh["tls_version"], "00")

    ext_count = min(len(sh["extensions"]), 99)
    alpn_tag = _ja4_alpn_tag(sh.get("alpn", ""))

    section_a = f"{proto}{ver}{ext_count:02d}{alpn_tag}"

    sorted_ext = sorted(sh["extensions"])
    inner = f"{sh['cipher_suite']},{','.join(str(e) for e in sorted_ext)}"
    section_b = _sha256_12(inner)

    return f"{section_a}_{section_b}"


# ─── JA4L (latency) ──────────────────────────────────────────────────────────

def _ja4l(key: tuple[str, int, str, int]) -> dict[str, Any] | None:
    """
    Retrieve JA4L data for a connection.

    JA4L measures the TCP handshake RTT: time from SYN to SYN-ACK.
    Returns {"rtt_ms": float, "client_ttl": int} or None.
    """
    return _tcp_rtt.get(key)


# ─── Session resumption ──────────────────────────────────────────────────────

def _session_resumption_info(ch: dict[str, Any]) -> dict[str, Any]:
    """
    Analyze ClientHello for TLS session resumption behavior.
    Returns a dict describing what resumption mechanisms the client uses.
    """
    mechanisms: list[str] = []

    if ch.get("has_session_ticket_data"):
        mechanisms.append("session_ticket")

    if ch.get("has_pre_shared_key"):
        mechanisms.append("psk")

    if ch.get("has_early_data"):
        mechanisms.append("early_data_0rtt")

    if ch.get("session_id") and len(ch["session_id"]) > 0:
        mechanisms.append("session_id")

    return {
        "resumption_attempted": len(mechanisms) > 0,
        "mechanisms": mechanisms,
    }


# ─── Session cleanup ─────────────────────────────────────────────────────────

def _cleanup_sessions() -> None:
    now = time.monotonic()
    stale = [k for k, ts in _session_ts.items() if now - ts > _SESSION_TTL]
    for k in stale:
        _sessions.pop(k, None)
        _session_ts.pop(k, None)
    # Also clean up TCP RTT tracking
    stale_syn = [k for k, v in _tcp_syn.items()
                 if now - v.get("time", 0) > _SESSION_TTL]
    for k in stale_syn:
        _tcp_syn.pop(k, None)
    stale_rtt = [k for k, _ in _tcp_rtt.items()
                 if k not in _sessions and k not in _session_ts]
    for k in stale_rtt:
        _tcp_rtt.pop(k, None)


# ─── Dedup cache ─────────────────────────────────────────────────────────────

# Key: (src_ip, event_type, fingerprint_key) → timestamp of last emit
_dedup_cache: dict[tuple[str, str, str], float] = {}
_DEDUP_CLEANUP_INTERVAL: float = 60.0
_dedup_last_cleanup: float = 0.0


def _dedup_key_for(event_type: str, fields: dict[str, Any]) -> str:
    """Build a dedup fingerprint from the most significant fields."""
    if event_type == "tls_client_hello":
        return fields.get("ja3", "") + "|" + fields.get("ja4", "")
    if event_type == "tls_session":
        return (fields.get("ja3", "") + "|" + fields.get("ja3s", "") +
                "|" + fields.get("ja4", "") + "|" + fields.get("ja4s", ""))
    if event_type == "tls_certificate":
        return fields.get("subject_cn", "") + "|" + fields.get("issuer", "")
    # tls_resumption or unknown — dedup on mechanisms
    return fields.get("mechanisms", fields.get("resumption", ""))


def _is_duplicate(event_type: str, fields: dict[str, Any]) -> bool:
    """Return True if this event was already emitted within the dedup window."""
    if _DEDUP_TTL <= 0:
        return False

    global _dedup_last_cleanup
    now = time.monotonic()

    # Periodic cleanup
    if now - _dedup_last_cleanup > _DEDUP_CLEANUP_INTERVAL:
        stale = [k for k, ts in _dedup_cache.items() if now - ts > _DEDUP_TTL]
        for k in stale:
            del _dedup_cache[k]
        _dedup_last_cleanup = now

    src_ip = fields.get("src_ip", "")
    fp = _dedup_key_for(event_type, fields)
    cache_key = (src_ip, event_type, fp)

    last_seen = _dedup_cache.get(cache_key)
    if last_seen is not None and now - last_seen < _DEDUP_TTL:
        return True

    _dedup_cache[cache_key] = now
    return False


# ─── Logging helpers ─────────────────────────────────────────────────────────

def _log(event_type: str, severity: int = SEVERITY_INFO, **fields: Any) -> None:
    if _is_duplicate(event_type, fields):
        return
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity=severity, **fields)
    write_syslog_file(line)


# ─── Packet callback ─────────────────────────────────────────────────────────

def _on_packet(pkt: Any) -> None:
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    src_ip: str = ip.src
    dst_ip: str = ip.dst
    src_port: int = tcp.sport
    dst_port: int = tcp.dport
    flags: int = tcp.flags.value if hasattr(tcp.flags, 'value') else int(tcp.flags)

    # ── TCP SYN tracking for JA4L ──
    if flags & _TCP_SYN and not (flags & _TCP_ACK):
        # Pure SYN — record timestamp and TTL
        key = (src_ip, src_port, dst_ip, dst_port)
        _tcp_syn[key] = {"time": time.monotonic(), "ttl": ip.ttl}

    elif flags & _TCP_SYN and flags & _TCP_ACK:
        # SYN-ACK — calculate RTT for the original SYN sender
        rev_key = (dst_ip, dst_port, src_ip, src_port)
        syn_data = _tcp_syn.pop(rev_key, None)
        if syn_data:
            rtt_ms = round((time.monotonic() - syn_data["time"]) * 1000, 2)
            _tcp_rtt[rev_key] = {
                "rtt_ms": rtt_ms,
                "client_ttl": syn_data["ttl"],
            }

    payload = bytes(tcp.payload)
    if not payload:
        return

    # TLS record check
    if payload[0] != _TLS_RECORD_HANDSHAKE:
        return

    # Attempt ClientHello parse
    ch = _parse_client_hello(payload)
    if ch is not None:
        _cleanup_sessions()

        key = (src_ip, src_port, dst_ip, dst_port)
        ja3_str, ja3_hash = _ja3(ch)
        ja4_hash = _ja4(ch)
        resumption = _session_resumption_info(ch)
        rtt_data = _ja4l(key)

        _sessions[key] = {
            "ja3": ja3_hash,
            "ja3_str": ja3_str,
            "ja4": ja4_hash,
            "tls_version": ch["tls_version"],
            "cipher_suites": ch["cipher_suites"],
            "extensions": ch["extensions"],
            "signature_algorithms": ch.get("signature_algorithms", []),
            "supported_versions": ch.get("supported_versions", []),
            "sni": ch["sni"],
            "alpn": ch["alpn"],
            "resumption": resumption,
        }
        _session_ts[key] = time.monotonic()

        log_fields: dict[str, Any] = {
            "src_ip": src_ip,
            "src_port": str(src_port),
            "dst_ip": dst_ip,
            "dst_port": str(dst_port),
            "ja3": ja3_hash,
            "ja4": ja4_hash,
            "tls_version": _tls_version_str(ch["tls_version"]),
            "sni": ch["sni"] or "",
            "alpn": ",".join(ch["alpn"]),
            "raw_ciphers": "-".join(str(c) for c in ch["cipher_suites"]),
            "raw_extensions": "-".join(str(e) for e in ch["extensions"]),
        }

        if resumption["resumption_attempted"]:
            log_fields["resumption"] = ",".join(resumption["mechanisms"])

        if rtt_data:
            log_fields["ja4l_rtt_ms"] = str(rtt_data["rtt_ms"])
            log_fields["ja4l_client_ttl"] = str(rtt_data["client_ttl"])

        _log("tls_client_hello", **log_fields)
        return

    # Attempt ServerHello parse
    sh = _parse_server_hello(payload)
    if sh is not None:
        # Reverse 4-tuple to find the matching ClientHello
        rev_key = (dst_ip, dst_port, src_ip, src_port)
        ch_data = _sessions.pop(rev_key, None)
        _session_ts.pop(rev_key, None)

        ja3s_str, ja3s_hash = _ja3s(sh)
        ja4s_hash = _ja4s(sh)

        fields: dict[str, Any] = {
            "src_ip": dst_ip,   # original attacker is now the destination
            "src_port": str(dst_port),
            "dst_ip": src_ip,
            "dst_port": str(src_port),
            "ja3s": ja3s_hash,
            "ja4s": ja4s_hash,
            "tls_version": _tls_version_str(sh["tls_version"]),
        }

        if ch_data:
            fields["ja3"] = ch_data["ja3"]
            fields["ja4"] = ch_data.get("ja4", "")
            fields["sni"] = ch_data["sni"] or ""
            fields["alpn"] = ",".join(ch_data["alpn"])
            fields["raw_ciphers"] = "-".join(str(c) for c in ch_data["cipher_suites"])
            fields["raw_extensions"] = "-".join(str(e) for e in ch_data["extensions"])
            if ch_data.get("resumption", {}).get("resumption_attempted"):
                fields["resumption"] = ",".join(ch_data["resumption"]["mechanisms"])

        rtt_data = _tcp_rtt.pop(rev_key, None)
        if rtt_data:
            fields["ja4l_rtt_ms"] = str(rtt_data["rtt_ms"])
            fields["ja4l_client_ttl"] = str(rtt_data["client_ttl"])

        _log("tls_session", severity=SEVERITY_WARNING, **fields)
        return

    # Attempt Certificate parse (TLS 1.2 only — 1.3 encrypts it)
    cert = _parse_certificate(payload)
    if cert is not None:
        # Match to a session — the cert comes from the server side
        rev_key = (dst_ip, dst_port, src_ip, src_port)
        ch_data = _sessions.get(rev_key)

        cert_fields: dict[str, Any] = {
            "src_ip": dst_ip,
            "src_port": str(dst_port),
            "dst_ip": src_ip,
            "dst_port": str(src_port),
            "subject_cn": cert["subject_cn"],
            "issuer": cert["issuer"],
            "self_signed": str(cert["self_signed"]).lower(),
            "not_before": cert["not_before"],
            "not_after": cert["not_after"],
        }
        if cert["sans"]:
            cert_fields["sans"] = ",".join(cert["sans"])
        if ch_data:
            cert_fields["sni"] = ch_data.get("sni", "")

        _log("tls_certificate", **cert_fields)


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _log("startup", msg=f"sniffer started node={NODE_NAME}")
    sniff(
        filter="tcp",
        prn=_on_packet,
        store=False,
    )
