"""
TLS fingerprinting engine for the fleet-wide MACVLAN sniffer.

Extracted from templates/sniffer/server.py. All pure-Python TLS parsing,
JA3/JA3S/JA4/JA4S/JA4L computation, session tracking, and dedup logic
lives here. The packet callback is parameterized to accept an IP-to-decky
mapping and a write function, so it works for fleet-wide sniffing.
"""

from __future__ import annotations

import hashlib
import struct
import time
from collections import deque
from typing import Any, Callable

from decnet.logging import get_logger
from decnet.prober.tcpfp import _extract_options_order
from decnet.sniffer.p0f import guess_os, hop_distance, initial_ttl
from decnet.sniffer.seq_class import classify_sequence
from decnet.sniffer.syslog import SEVERITY_INFO, SEVERITY_WARNING, syslog_line
from decnet.telemetry import traced as _traced, get_tracer as _get_tracer

_log = get_logger("sniffer.fingerprint")

# ─── Constants ───────────────────────────────────────────────────────────────

SERVICE_NAME: str = "sniffer"

_SESSION_TTL: float = 60.0
_DEDUP_TTL: float = 300.0

# Inactivity after which a TCP flow is considered closed and its timing
# summary is flushed as an event.
_FLOW_IDLE_TIMEOUT: float = 120.0

_GREASE: frozenset[int] = frozenset(0x0A0A + i * 0x1010 for i in range(16))

_TLS_RECORD_HANDSHAKE: int = 0x16
_TLS_HT_CLIENT_HELLO: int = 0x01
_TLS_HT_SERVER_HELLO: int = 0x02
_TLS_HT_CERTIFICATE: int = 0x0B

_EXT_SNI: int = 0x0000
_EXT_SUPPORTED_GROUPS: int = 0x000A
_EXT_EC_POINT_FORMATS: int = 0x000B
_EXT_SIGNATURE_ALGORITHMS: int = 0x000D
_EXT_ALPN: int = 0x0010
_EXT_SESSION_TICKET: int = 0x0023
_EXT_SUPPORTED_VERSIONS: int = 0x002B
_EXT_PRE_SHARED_KEY: int = 0x0029
_EXT_EARLY_DATA: int = 0x002A

_TCP_SYN: int = 0x02
_TCP_ACK: int = 0x10
_TCP_FIN: int = 0x01
_TCP_RST: int = 0x04

# Event types that should fan out on the service bus as ``decky.{id}.traffic``.
# Intermediate parser artifacts (tls_client_hello, tls_certificate) are
# intentionally excluded — tls_session covers the completed handshake and
# tcp_flow_timing covers the flow summary; together they're the minimum
# interesting signal for downstream consumers.
_BUS_TRAFFIC_EVENTS: frozenset[str] = frozenset({
    "tls_session",
    "tcp_flow_timing",
    "tcp_syn_fingerprint",
    "ssh_client_banner",
    "quic_client_hello",
    "http_request_fingerprint",
    "http2_settings",
    "http3_settings",
})


def _parse_ssh_banner(data: bytes) -> str | None:
    """
    Return the attacker's SSH identification string (RFC 4253 §4.2) if
    *data* begins with one, else None.

    A valid banner starts with ``SSH-`` and terminates at the first CR or LF
    within the 255-byte RFC-mandated window.  The returned string is decoded
    as ASCII and stripped of the trailing CR/LF bytes.
    """
    if not data.startswith(b"SSH-"):
        return None
    end = -1
    # RFC 4253: identification string (incl. CR LF) must not exceed 255 bytes.
    for i, b in enumerate(data[:255]):
        if b in (0x0D, 0x0A):  # CR or LF
            end = i
            break
    if end < 5:  # "SSH-X" minimum
        return None
    try:
        return data[:end].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return None


# ─── TCP option extraction for passive fingerprinting ───────────────────────

def _extract_tcp_fingerprint(tcp_options: list) -> dict[str, Any]:
    """
    Extract MSS, window-scale, SACK, timestamp flags, and the options order
    signature from a scapy TCP options list.
    """
    mss = 0
    wscale: int | None = None
    sack_ok = False
    has_ts = False
    for opt_name, opt_value in tcp_options or []:
        if opt_name == "MSS":
            mss = opt_value
        elif opt_name == "WScale":
            wscale = opt_value
        elif opt_name in ("SAckOK", "SAck"):
            sack_ok = True
        elif opt_name == "Timestamp":
            has_ts = True
    options_sig = _extract_options_order(tcp_options or [])
    return {
        "mss": mss,
        "wscale": wscale,
        "sack_ok": sack_ok,
        "has_timestamps": has_ts,
        "options_sig": options_sig,
    }


# ─── GREASE helpers ──────────────────────────────────────────────────────────

def _is_grease(value: int) -> bool:
    return value in _GREASE


def _filter_grease(values: list[int]) -> list[int]:
    return [v for v in values if not _is_grease(v)]


# ─── TLS parsers ─────────────────────────────────────────────────────────────

@_traced("sniffer.parse_client_hello")
def _parse_client_hello(data: bytes) -> dict[str, Any] | None:
    try:
        if len(data) < 6:
            return None
        if data[0] != _TLS_RECORD_HANDSHAKE:
            return None
        record_len = struct.unpack_from("!H", data, 3)[0]
        if len(data) < 5 + record_len:
            return None

        hs = data[5:]
        if hs[0] != _TLS_HT_CLIENT_HELLO:
            return None

        hs_len = struct.unpack_from("!I", b"\x00" + hs[1:4])[0]
        body = hs[4: 4 + hs_len]
        if len(body) < 34:
            return None

        pos = 0
        tls_version = struct.unpack_from("!H", body, pos)[0]
        pos += 2
        pos += 32  # Random

        session_id_len = body[pos]
        session_id = body[pos + 1: pos + 1 + session_id_len]
        pos += 1 + session_id_len

        cs_len = struct.unpack_from("!H", body, pos)[0]
        pos += 2
        cipher_suites = [
            struct.unpack_from("!H", body, pos + i * 2)[0]
            for i in range(cs_len // 2)
        ]
        pos += cs_len

        comp_len = body[pos]
        pos += 1 + comp_len

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


@_traced("sniffer.parse_server_hello")
def _parse_server_hello(data: bytes) -> dict[str, Any] | None:
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
        pos += 32  # Random

        session_id_len = body[pos]
        pos += 1 + session_id_len

        if pos + 2 > len(body):
            return None

        cipher_suite = struct.unpack_from("!H", body, pos)[0]
        pos += 2
        pos += 1  # Compression method

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


@_traced("sniffer.parse_certificate")
def _parse_certificate(data: bytes) -> dict[str, Any] | None:
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

        certs_len = struct.unpack_from("!I", b"\x00" + body[0:3])[0]
        if certs_len == 0:
            return None

        pos = 3
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
    tag, content_start, length = _der_read_tag_len(data, pos)
    return content_start, length


def _der_read_oid(data: bytes, pos: int, length: int) -> str:
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
    pos = start
    end = start + length
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
                if oid == "2.5.4.3":
                    val_tag, val_start, val_len = _der_read_tag_len(data, oid_start + oid_len)
                    return data[val_start: val_start + val_len].decode("utf-8", errors="replace")
            attr_pos = seq_start + seq_len
        pos = set_end
    return ""


def _der_extract_name_str(data: bytes, start: int, length: int) -> str:
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
    try:
        outer_start, outer_len = _der_read_sequence(cert_der, 0)
        tbs_tag, tbs_start, tbs_len = _der_read_tag_len(cert_der, outer_start)
        tbs_end = tbs_start + tbs_len
        pos = tbs_start

        if cert_der[pos] == 0xA0:
            _, v_start, v_len = _der_read_tag_len(cert_der, pos)
            pos = v_start + v_len

        _, sn_start, sn_len = _der_read_tag_len(cert_der, pos)
        pos = sn_start + sn_len

        _, sa_start, sa_len = _der_read_tag_len(cert_der, pos)
        pos = sa_start + sa_len

        issuer_tag, issuer_start, issuer_len = _der_read_tag_len(cert_der, pos)
        issuer_str = _der_extract_name_str(cert_der, issuer_start, issuer_len)
        issuer_cn = _der_extract_cn(cert_der, issuer_start, issuer_len)
        pos = issuer_start + issuer_len

        val_tag, val_start, val_len = _der_read_tag_len(cert_der, pos)
        nb_tag, nb_start, nb_len = _der_read_tag_len(cert_der, val_start)
        not_before = cert_der[nb_start: nb_start + nb_len].decode("ascii", errors="replace")
        na_tag, na_start, na_len = _der_read_tag_len(cert_der, nb_start + nb_len)
        not_after = cert_der[na_start: na_start + na_len].decode("ascii", errors="replace")
        pos = val_start + val_len

        subj_tag, subj_start, subj_len = _der_read_tag_len(cert_der, pos)
        subject_cn = _der_extract_cn(cert_der, subj_start, subj_len)
        subject_str = _der_extract_name_str(cert_der, subj_start, subj_len)

        self_signed = (issuer_cn == subject_cn) and subject_cn != ""

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
    sans: list[str] = []
    try:
        if pos >= end:
            return sans
        spki_tag, spki_start, spki_len = _der_read_tag_len(cert_der, pos)
        pos = spki_start + spki_len

        while pos < end:
            tag = cert_der[pos]
            if tag == 0xA3:
                _, ext_wrap_start, ext_wrap_len = _der_read_tag_len(cert_der, pos)
                _, exts_start, exts_len = _der_read_tag_len(cert_der, ext_wrap_start)
                epos = exts_start
                eend = exts_start + exts_len
                while epos < eend:
                    ext_tag, ext_start, ext_len = _der_read_tag_len(cert_der, epos)
                    ext_end = ext_start + ext_len
                    oid_tag, oid_start, oid_len = _der_read_tag_len(cert_der, ext_start)
                    if oid_tag == 0x06:
                        oid = _der_read_oid(cert_der, oid_start, oid_len)
                        if oid == "2.5.29.17":
                            vpos = oid_start + oid_len
                            if vpos < ext_end and cert_der[vpos] == 0x01:
                                _, bs, bl = _der_read_tag_len(cert_der, vpos)
                                vpos = bs + bl
                            if vpos < ext_end:
                                os_tag, os_start, os_len = _der_read_tag_len(cert_der, vpos)
                                if os_tag == 0x04:
                                    sans = _parse_san_sequence(cert_der, os_start, os_len)
                    epos = ext_end
                break
            else:
                _, skip_start, skip_len = _der_read_tag_len(cert_der, pos)
                pos = skip_start + skip_len
    except Exception:  # nosec B110 — DER parse errors return partial results
        pass
    return sans


def _parse_san_sequence(data: bytes, start: int, length: int) -> list[str]:
    names: list[str] = []
    try:
        seq_tag, seq_start, seq_len = _der_read_tag_len(data, start)
        pos = seq_start
        end = seq_start + seq_len
        while pos < end:
            tag = data[pos]
            _, val_start, val_len = _der_read_tag_len(data, pos)
            context_tag = tag & 0x1F
            if context_tag == 2:
                names.append(data[val_start: val_start + val_len].decode("ascii", errors="replace"))
            elif context_tag == 7 and val_len == 4:
                names.append(".".join(str(b) for b in data[val_start: val_start + val_len]))
            pos = val_start + val_len
    except Exception:  # nosec B110 — SAN parse errors return partial results
        pass
    return names


# ─── JA3 / JA3S ─────────────────────────────────────────────────────────────

def _tls_version_str(version: int) -> str:
    return {
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
        0x0200: "SSL 2.0",
        0x0300: "SSL 3.0",
    }.get(version, f"0x{version:04x}")


@_traced("sniffer.ja3")
def _ja3(ch: dict[str, Any]) -> tuple[str, str]:
    parts = [
        str(ch["tls_version"]),
        "-".join(str(c) for c in ch["cipher_suites"]),
        "-".join(str(e) for e in ch["extensions"]),
        "-".join(str(g) for g in ch["supported_groups"]),
        "-".join(str(p) for p in ch["ec_point_formats"]),
    ]
    ja3_str = ",".join(parts)
    return ja3_str, hashlib.md5(ja3_str.encode(), usedforsecurity=False).hexdigest()


@_traced("sniffer.ja3s")
def _ja3s(sh: dict[str, Any]) -> tuple[str, str]:
    parts = [
        str(sh["tls_version"]),
        str(sh["cipher_suite"]),
        "-".join(str(e) for e in sh["extensions"]),
    ]
    ja3s_str = ",".join(parts)
    return ja3s_str, hashlib.md5(ja3s_str.encode(), usedforsecurity=False).hexdigest()


# ─── JA4 / JA4S ─────────────────────────────────────────────────────────────

def _ja4_version(ch: dict[str, Any]) -> str:
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
    return hashlib.sha256(text.encode()).hexdigest()[:12]


@_traced("sniffer.ja4")
def _ja4(ch: dict[str, Any]) -> str:
    proto = "t"
    ver = _ja4_version(ch)
    sni_flag = "d" if ch.get("sni") else "i"
    cs_count = min(len(ch["cipher_suites"]), 99)
    ext_count = min(len(ch["extensions"]), 99)
    alpn_tag = _ja4_alpn_tag(ch.get("alpn", []))
    section_a = f"{proto}{ver}{sni_flag}{cs_count:02d}{ext_count:02d}{alpn_tag}"
    sorted_cs = sorted(ch["cipher_suites"])
    section_b = _sha256_12(",".join(str(c) for c in sorted_cs))
    sorted_ext = sorted(ch["extensions"])
    sorted_sa = sorted(ch.get("signature_algorithms", []))
    ext_str = ",".join(str(e) for e in sorted_ext)
    sa_str = ",".join(str(s) for s in sorted_sa)
    combined = f"{ext_str}_{sa_str}" if sa_str else ext_str
    section_c = _sha256_12(combined)
    return f"{section_a}_{section_b}_{section_c}"


@_traced("sniffer.ja4s")
def _ja4s(sh: dict[str, Any]) -> str:
    proto = "t"
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


# ─── JA4H (HTTP-layer fingerprint) ─────────────────────────────────────────

def _ja4h(
    method: str,
    version: str,
    headers_ordered: list[str],
    cookie_val: str = "",
    accept_lang: str = "",
) -> str:
    """Compute JA4H per the FoxIO public spec.

    ``headers_ordered`` is the sequence of header NAMES as emitted by the
    decnet_jsonl Caddy log encoder (arrival order preserved for h1; HPACK/
    QPACK decode order for h2/h3 — the order the client chose).
    Cookie and Referer are extracted before the header hash.
    """
    method_tag = (method[:2].upper() if method else "UN")
    ver_map = {
        "HTTP/1.0": "10", "HTTP/1.1": "11", "HTTP/2.0": "20", "HTTP/3.0": "30",
        "1.0": "10", "1.1": "11", "2.0": "20", "3.0": "30",
        "2": "20", "3": "30",
    }
    ver_tag = ver_map.get(version.upper().lstrip("HTTP/"), ver_map.get(version.upper(), "00"))
    has_cookie = "c" if any(h.lower() == "cookie" for h in headers_ordered) else "n"
    has_referer = "r" if any(h.lower() == "referer" for h in headers_ordered) else "n"
    lang_tag = (accept_lang[:4].ljust(4, "0") if accept_lang else "0000")
    filtered = [h for h in headers_ordered if h.lower() not in ("cookie", "referer")]
    count_tag = f"{min(len(filtered), 99):02d}"
    header_hash = _sha256_12(",".join(h.lower() for h in filtered))
    if cookie_val:
        pairs = sorted(p.strip() for p in cookie_val.split(";") if "=" in p.strip())
        cookie_hash = _sha256_12(";".join(pairs))
    else:
        cookie_hash = "000000000000"
    return f"{method_tag}{ver_tag}{has_cookie}{has_referer}{lang_tag}_{count_tag}_{header_hash}_{cookie_hash}"


# ─── QUIC Initial packet decryption ─────────────────────────────────────────

_QUIC_V1_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract(SHA-256) = HMAC-SHA256(salt, IKM)."""
    import hmac as _hmac
    return _hmac.new(salt, ikm, "sha256").digest()


def _hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    """HKDF-Expand-Label per RFC 8446 §7.1."""
    label_bytes = b"tls13 " + label.encode()
    hkdf_label = (
        struct.pack("!H", length)
        + bytes([len(label_bytes)]) + label_bytes
        + bytes([len(context)]) + context
    )
    # HKDF-Expand with T(0) = empty; T(n) = HMAC-SHA256(secret, T(n-1) || info || n)
    import hmac as _hmac
    t = b""
    okm = b""
    for i in range(1, (length + 32 - 1) // 32 + 1):
        t = _hmac.new(secret, t + hkdf_label + bytes([i]), "sha256").digest()
        okm += t
    return okm[:length]


def _quic_initial_keys(dcid: bytes) -> tuple[bytes, bytes, bytes]:
    """Derive (key, iv, hp) for QUIC v1 Initial client packets."""
    initial_secret = _hkdf_extract(_QUIC_V1_INITIAL_SALT, dcid)
    client_secret = _hkdf_expand_label(initial_secret, "client in", b"", 32)
    key = _hkdf_expand_label(client_secret, "quic key", b"", 16)
    iv = _hkdf_expand_label(client_secret, "quic iv", b"", 12)
    hp = _hkdf_expand_label(client_secret, "quic hp", b"", 16)
    return key, iv, hp


def _quic_varint(data: bytes | bytearray, offset: int) -> tuple[int, int]:
    """Parse QUIC variable-length integer. Returns (value, new_offset)."""
    b0 = data[offset]
    msb = (b0 & 0xC0) >> 6
    if msb == 0:
        return b0 & 0x3F, offset + 1
    if msb == 1:
        return struct.unpack_from("!H", data, offset)[0] & 0x3FFF, offset + 2
    if msb == 2:
        return struct.unpack_from("!I", data, offset)[0] & 0x3FFFFFFF, offset + 4
    return struct.unpack_from("!Q", data, offset)[0] & 0x3FFFFFFFFFFFFFFF, offset + 8


def _aes128gcm_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes | None:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception:
        return None


def _remove_hp_long(data: bytearray, pn_offset: int, sample_offset: int, hp_key: bytes) -> None:
    """Remove QUIC long-header packet number protection in-place."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    sample = bytes(data[sample_offset:sample_offset + 16])
    mask = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor().update(sample)  # nosec B305 — RFC 9001 §5.4.3 mandates AES-ECB for QUIC header-protection
    data[0] ^= mask[0] & 0x0F  # long header: low 4 bits protected
    pn_len = (data[0] & 0x03) + 1
    for i in range(pn_len):
        data[pn_offset + i] ^= mask[1 + i]


def _extract_crypto_frames(plaintext: bytes) -> bytes:
    """Reassemble CRYPTO frame data from decrypted QUIC Initial payload."""
    segments: dict[int, bytes] = {}
    pos = 0
    while pos < len(plaintext):
        if plaintext[pos] in (0x00, 0x01):  # PADDING / PING
            pos += 1
            continue
        try:
            frame_type, pos = _quic_varint(plaintext, pos)
        except Exception:
            break
        if frame_type == 0x06:  # CRYPTO
            try:
                crypto_offset, pos = _quic_varint(plaintext, pos)
                length, pos = _quic_varint(plaintext, pos)
                if pos + length > len(plaintext):
                    break
                segments[crypto_offset] = plaintext[pos:pos + length]
                pos += length
            except Exception:
                break
        else:
            break  # unknown frame — stop
    if not segments:
        return b""
    result = b""
    expected = 0
    for off in sorted(segments):
        if off != expected:
            break
        result += segments[off]
        expected += len(segments[off])
    return result


def _parse_quic_initial(udp_payload: bytes) -> "dict[str, Any] | None":
    """
    Decrypt a QUIC v1 Initial packet and extract the TLS ClientHello.
    Returns the same dict shape as _parse_client_hello(), or None.

    Key derivation per RFC 9001 §5.2. Header protection per §5.4.3.
    Only processes QUIC v1 (0x00000001) Initial packets.
    """
    if len(udp_payload) < 7:
        return None
    data = bytearray(udp_payload)
    # Must be long header (bit 7) with Initial type (bits 4-5 = 00)
    if not (data[0] & 0x80) or (data[0] & 0x30) != 0x00:
        return None
    version = struct.unpack_from("!I", data, 1)[0]
    if version != 0x00000001:
        return None
    pos = 5
    dcid_len = data[pos]
    pos += 1
    if pos + dcid_len > len(data):
        return None
    dcid = bytes(data[pos:pos + dcid_len])
    pos += dcid_len
    scid_len = data[pos]
    pos += 1
    pos += scid_len
    try:
        token_len, pos = _quic_varint(data, pos)
        pos += token_len
        pkt_len, pos = _quic_varint(data, pos)
    except Exception:
        return None
    pn_offset = pos
    payload_end = pos + pkt_len
    if payload_end > len(data):
        return None
    try:
        key, iv, hp = _quic_initial_keys(dcid)
    except Exception:
        return None
    sample_offset = pn_offset + 4
    if sample_offset + 16 > payload_end:
        return None
    _remove_hp_long(data, pn_offset, sample_offset, hp)
    pn_len = (data[0] & 0x03) + 1
    pn = 0
    for i in range(pn_len):
        pn = (pn << 8) | data[pn_offset + i]
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    aad = bytes(data[:pn_offset + pn_len])
    ciphertext = bytes(data[pn_offset + pn_len:payload_end])
    plaintext = _aes128gcm_decrypt(key, nonce, aad, ciphertext)
    if plaintext is None:
        return None
    crypto_data = _extract_crypto_frames(plaintext)
    if not crypto_data:
        return None
    # QUIC CRYPTO frames carry TLS handshake WITHOUT the record layer.
    # Wrap in a fake TLS record so _parse_client_hello can consume it.
    fake_record = bytes([0x16, 0x03, 0x01]) + struct.pack("!H", len(crypto_data)) + crypto_data
    return _parse_client_hello(fake_record)


# ─── JA4-QUIC ────────────────────────────────────────────────────────────────

@_traced("sniffer.ja4_quic")
def _ja4_quic(ch: "dict[str, Any]") -> str:
    """JA4-QUIC: JA4 with proto prefix 'q' (FoxIO spec, QUIC transport variant)."""
    proto = "q"
    ver = _ja4_version(ch)
    sni_flag = "d" if ch.get("sni") else "i"
    cs_count = min(len(ch["cipher_suites"]), 99)
    ext_count = min(len(ch["extensions"]), 99)
    alpn_tag = _ja4_alpn_tag(ch.get("alpn", []))
    section_a = f"{proto}{ver}{sni_flag}{cs_count:02d}{ext_count:02d}{alpn_tag}"
    section_b = _sha256_12(",".join(str(c) for c in sorted(ch["cipher_suites"])))
    sorted_ext = sorted(ch["extensions"])
    sorted_sa = sorted(ch.get("signature_algorithms", []))
    ext_str = ",".join(str(e) for e in sorted_ext)
    combined = f"{ext_str}_{','.join(str(s) for s in sorted_sa)}" if sorted_sa else ext_str
    section_c = _sha256_12(combined)
    return f"{section_a}_{section_b}_{section_c}"


# ─── JA4L (latency) ─────────────────────────────────────────────────────────

def _ja4l(
    key: tuple[str, int, str, int],
    tcp_rtt: dict[tuple[str, int, str, int], dict[str, Any]],
) -> dict[str, Any] | None:
    return tcp_rtt.get(key)


# ─── Session resumption ─────────────────────────────────────────────────────

@_traced("sniffer.session_resumption_info")
def _session_resumption_info(ch: dict[str, Any]) -> dict[str, Any]:
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


# ─── Sniffer engine (stateful, one instance per worker) ─────────────────────

class SnifferEngine:
    """
    Stateful TLS fingerprinting engine. Tracks sessions, TCP RTTs,
    and dedup state. Thread-safe only when called from a single thread
    (the scapy sniff thread).
    """

    def __init__(
        self,
        ip_to_decky: dict[str, str],
        write_fn: Callable[[str], None],
        dedup_ttl: float = 300.0,
        publish_fn: Callable[[str, str, dict[str, Any]], None] | None = None,
    ):
        self._ip_to_decky = ip_to_decky
        self._write_fn = write_fn
        self._dedup_ttl = dedup_ttl
        # Optional bus publish hook. Called *after* dedup + syslog write, so
        # every syslog line we emit has a matching bus event and duplicate
        # storms are already suppressed upstream.  Signature:
        # ``publish_fn(decky_name, event_type, payload_dict)``.
        self._publish_fn = publish_fn

        self._sessions: dict[tuple[str, int, str, int], dict[str, Any]] = {}
        self._session_ts: dict[tuple[str, int, str, int], float] = {}
        self._tcp_syn: dict[tuple[str, int, str, int], dict[str, Any]] = {}
        self._tcp_rtt: dict[tuple[str, int, str, int], dict[str, Any]] = {}

        # Per-source-IP rolling samples for sequence-pattern classification.
        # IP-ID and TCP ISN need multiple SYNs from the same attacker before
        # we can label them random/incremental/zero/constant.
        self._SEQ_SAMPLE_SIZE = 8
        self._ipid_samples: dict[str, deque[int]] = {}
        self._isn_samples: dict[str, deque[int]] = {}

        # Per-flow timing aggregator. Key: (src_ip, src_port, dst_ip, dst_port).
        # Flow direction is client→decky; reverse packets are associated back
        # to the forward flow so we can track retransmits and inter-arrival.
        self._flows: dict[tuple[str, int, str, int], dict[str, Any]] = {}
        self._flow_last_cleanup: float = 0.0
        self._FLOW_CLEANUP_INTERVAL: float = 30.0

        self._dedup_cache: dict[tuple[str, str, str], float] = {}
        self._dedup_last_cleanup: float = 0.0
        self._DEDUP_CLEANUP_INTERVAL: float = 60.0

    def update_ip_map(self, ip_to_decky: dict[str, str]) -> None:
        self._ip_to_decky = ip_to_decky

    def _resolve_decky(self, src_ip: str, dst_ip: str) -> str | None:
        """Map a packet to a decky name. Returns None if neither IP is a known decky."""
        if dst_ip in self._ip_to_decky:
            return self._ip_to_decky[dst_ip]
        if src_ip in self._ip_to_decky:
            return self._ip_to_decky[src_ip]
        return None

    def _cleanup_sessions(self) -> None:
        now = time.monotonic()
        stale = [k for k, ts in self._session_ts.items() if now - ts > _SESSION_TTL]
        for k in stale:
            self._sessions.pop(k, None)
            self._session_ts.pop(k, None)
        stale_syn = [k for k, v in self._tcp_syn.items()
                     if now - v.get("time", 0) > _SESSION_TTL]
        for k in stale_syn:
            self._tcp_syn.pop(k, None)
        stale_rtt = [k for k, _ in self._tcp_rtt.items()
                     if k not in self._sessions and k not in self._session_ts]
        for k in stale_rtt:
            self._tcp_rtt.pop(k, None)

    def _dedup_key_for(self, event_type: str, fields: dict[str, Any]) -> str:
        if event_type == "tls_client_hello":
            return fields.get("ja3", "") + "|" + fields.get("ja4", "")
        if event_type == "tls_session":
            return (fields.get("ja3", "") + "|" + fields.get("ja3s", "") +
                    "|" + fields.get("ja4", "") + "|" + fields.get("ja4s", ""))
        if event_type == "tls_certificate":
            return fields.get("subject_cn", "") + "|" + fields.get("issuer", "")
        if event_type == "tcp_syn_fingerprint":
            # Dedupe per (OS signature, options layout, sequence-pattern
            # classification). Including ipid_class/isn_class lets each
            # transition (unknown → random/incremental/zero/constant) emit
            # exactly one fresh event as samples accumulate.
            return (
                fields.get("os_guess", "")
                + "|" + fields.get("options_sig", "")
                + "|" + fields.get("ipid_class", "")
                + "|" + fields.get("isn_class", "")
            )
        if event_type == "tcp_flow_timing":
            # Dedup per (attacker_ip, decky_port) — src_port is deliberately
            # excluded so a port scanner rotating source ports only produces
            # one timing event per dedup window. Behavior cadence doesn't
            # need per-ephemeral-port fidelity.
            return fields.get("dst_ip", "") + "|" + fields.get("dst_port", "")
        if event_type == "quic_client_hello":
            return fields.get("src_ip", "") + "|" + fields.get("ja4_quic", "")
        if event_type == "http_request_fingerprint":
            return fields.get("src_ip", "") + "|" + fields.get("ja4h", "")
        if event_type in ("http2_settings", "http3_settings"):
            return fields.get("src_ip", "") + "|" + str(fields.get("settings_hash", ""))
        return fields.get("mechanisms", fields.get("resumption", ""))

    def _is_duplicate(self, event_type: str, fields: dict[str, Any]) -> bool:
        if self._dedup_ttl <= 0:
            return False
        now = time.monotonic()
        if now - self._dedup_last_cleanup > self._DEDUP_CLEANUP_INTERVAL:
            stale = [k for k, ts in self._dedup_cache.items() if now - ts > self._dedup_ttl]
            for k in stale:
                del self._dedup_cache[k]
            self._dedup_last_cleanup = now
        src_ip = fields.get("src_ip", "")
        fp = self._dedup_key_for(event_type, fields)
        cache_key = (src_ip, event_type, fp)
        last_seen = self._dedup_cache.get(cache_key)
        if last_seen is not None and now - last_seen < self._dedup_ttl:
            return True
        self._dedup_cache[cache_key] = now
        return False

    def _log(self, node_name: str, event_type: str, severity: int = SEVERITY_INFO, **fields: Any) -> None:
        if self._is_duplicate(event_type, fields):
            return
        line = syslog_line(SERVICE_NAME, node_name, event_type, severity=severity, **fields)
        self._write_fn(line)
        # Bus fan-out, fire-and-forget.  Only emit for traffic-summary event
        # types — the ones that represent an observable decky interaction
        # rather than an intermediate parser artifact.  Rate is naturally
        # bounded by the dedup cache above.
        if self._publish_fn is not None and event_type in _BUS_TRAFFIC_EVENTS:
            try:
                self._publish_fn(node_name, event_type, dict(fields))
            except Exception:  # nosec B110 — bus must never break sniff thread
                pass

    # ── QUIC packet callback (separate UDP/443 sniff thread) ─────────────────

    def on_quic_packet(self, pkt: Any) -> None:
        """Packet callback for the UDP/443 QUIC Initial sniff thread."""
        try:
            from scapy.layers.inet import IP, UDP
            if not pkt.haslayer(UDP):
                return
            udp = pkt[UDP]
            if udp.dport != 443:
                return
            ip = pkt[IP] if pkt.haslayer(IP) else None
            if ip is None:
                return
            src_ip: str = ip.src
            dst_ip: str = ip.dst
            node_name = self._ip_to_decky.get(dst_ip)
            if node_name is None:
                return
            payload = bytes(udp.payload)
            ch = _parse_quic_initial(payload)
            if ch is None:
                return
            ja4q = _ja4_quic(ch)
            self._log(
                node_name,
                "quic_client_hello",
                severity=SEVERITY_WARNING,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port="443",
                ja4_quic=ja4q,
                sni=ch.get("sni", ""),
                alpn=",".join(ch.get("alpn", [])),
                raw_ciphers="-".join(str(c) for c in ch.get("cipher_suites", [])),
            )
        except Exception as exc:
            _log.debug("on_quic_packet: unhandled error for %s: %s", src_ip, exc)

    # ── Flow tracking (per-TCP-4-tuple timing + retransmits) ────────────────

    def _flow_key(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> tuple[str, int, str, int]:
        """
        Canonicalize a packet to the *client→decky* direction so forward and
        reverse packets share one flow record.
        """
        if dst_ip in self._ip_to_decky:
            return (src_ip, src_port, dst_ip, dst_port)
        # Otherwise src is the decky, flip.
        return (dst_ip, dst_port, src_ip, src_port)

    def _update_flow(
        self,
        flow_key: tuple[str, int, str, int],
        now: float,
        seq: int,
        payload_len: int,
        direction_forward: bool,
    ) -> None:
        """Record one packet into the flow aggregator."""
        flow = self._flows.get(flow_key)
        if flow is None:
            flow = {
                "start": now,
                "last": now,
                "packets": 0,
                "bytes": 0,
                "iat_sum": 0.0,
                "iat_min": float("inf"),
                "iat_max": 0.0,
                "iat_count": 0,
                "forward_seqs": set(),
                "retransmits": 0,
                "emitted": False,
            }
            self._flows[flow_key] = flow

        if flow["packets"] > 0:
            iat = now - flow["last"]
            if iat >= 0:
                flow["iat_sum"] += iat
                flow["iat_count"] += 1
                if iat < flow["iat_min"]:
                    flow["iat_min"] = iat
                if iat > flow["iat_max"]:
                    flow["iat_max"] = iat

        flow["last"] = now
        flow["packets"] += 1
        flow["bytes"] += payload_len

        # Retransmit detection: a forward-direction packet with payload whose
        # sequence number we've already seen is a retransmit. Empty SYN/ACKs
        # are excluded because they share seq legitimately.
        if direction_forward and payload_len > 0:
            if seq in flow["forward_seqs"]:
                flow["retransmits"] += 1
            else:
                flow["forward_seqs"].add(seq)

    def _flush_flow(
        self,
        flow_key: tuple[str, int, str, int],
        node_name: str,
    ) -> None:
        """Emit one `tcp_flow_timing` event for *flow_key* and drop its state.

        Trivial flows (scan probes: 1–2 packets, sub-second duration) are
        dropped silently — they add noise to the log pipeline without carrying
        usable behavioral signal (beacon cadence, exfil timing, retransmits
        are all meaningful only on longer-lived flows).
        """
        flow = self._flows.pop(flow_key, None)
        if flow is None or flow.get("emitted"):
            return
        flow["emitted"] = True

        # Skip uninteresting flows — keep the log pipeline from being flooded
        # by short-lived scan probes.
        duration = flow["last"] - flow["start"]
        if flow["packets"] < 4 and flow["retransmits"] == 0 and duration < 1.0:
            return

        src_ip, src_port, dst_ip, dst_port = flow_key
        iat_count = flow["iat_count"]
        mean_iat_ms = round((flow["iat_sum"] / iat_count) * 1000, 2) if iat_count else 0.0
        min_iat_ms = round(flow["iat_min"] * 1000, 2) if iat_count else 0.0
        max_iat_ms = round(flow["iat_max"] * 1000, 2) if iat_count else 0.0
        duration_s = round(duration, 3)

        self._log(
            node_name,
            "tcp_flow_timing",
            src_ip=src_ip,
            src_port=str(src_port),
            dst_ip=dst_ip,
            dst_port=str(dst_port),
            packets=str(flow["packets"]),
            bytes=str(flow["bytes"]),
            duration_s=str(duration_s),
            mean_iat_ms=str(mean_iat_ms),
            min_iat_ms=str(min_iat_ms),
            max_iat_ms=str(max_iat_ms),
            retransmits=str(flow["retransmits"]),
        )

    def flush_all_flows(self) -> None:
        """
        Flush every tracked flow (emit `tcp_flow_timing` events) and drop
        state. Safe to call from outside the sniff thread; used during
        shutdown and in tests.
        """
        for key in list(self._flows.keys()):
            decky = self._ip_to_decky.get(key[2])
            if decky:
                self._flush_flow(key, decky)
            else:
                self._flows.pop(key, None)

    def _flush_idle_flows(self) -> None:
        """Flush any flow whose last packet was more than _FLOW_IDLE_TIMEOUT ago."""
        now = time.monotonic()
        if now - self._flow_last_cleanup < self._FLOW_CLEANUP_INTERVAL:
            return
        self._flow_last_cleanup = now
        stale: list[tuple[str, int, str, int]] = [
            k for k, f in self._flows.items()
            if now - f["last"] > _FLOW_IDLE_TIMEOUT
        ]
        for key in stale:
            decky = self._ip_to_decky.get(key[2])
            if decky:
                self._flush_flow(key, decky)
            else:
                self._flows.pop(key, None)

    def on_packet(self, pkt: Any) -> None:
        """Process a single scapy packet. Called from the sniff thread."""
        try:
            from scapy.layers.inet import IP, TCP
        except ImportError:
            return

        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]

        src_ip: str = ip.src
        dst_ip: str = ip.dst
        src_port: int = tcp.sport
        dst_port: int = tcp.dport
        flags: int = tcp.flags.value if hasattr(tcp.flags, 'value') else int(tcp.flags)

        # Skip traffic not involving any decky
        node_name = self._resolve_decky(src_ip, dst_ip)
        if node_name is None:
            return

        now = time.monotonic()

        # Per-flow timing aggregation (covers all TCP traffic, not just TLS)
        flow_key = self._flow_key(src_ip, src_port, dst_ip, dst_port)
        direction_forward = (flow_key[0] == src_ip and flow_key[1] == src_port)
        tcp_payload_len = len(bytes(tcp.payload))
        self._update_flow(
            flow_key,
            now=now,
            seq=int(tcp.seq),
            payload_len=tcp_payload_len,
            direction_forward=direction_forward,
        )
        self._flush_idle_flows()

        # TCP SYN tracking for JA4L + passive SYN fingerprint
        if flags & _TCP_SYN and not (flags & _TCP_ACK):
            key = (src_ip, src_port, dst_ip, dst_port)
            self._tcp_syn[key] = {"time": now, "ttl": ip.ttl}

            # Emit passive OS fingerprint on the *client* SYN. Only do this
            # when the destination is a known decky, i.e. we're seeing an
            # attacker's initial packet.
            if dst_ip in self._ip_to_decky:
                _tracer = _get_tracer("sniffer")
                with _tracer.start_as_current_span("sniffer.tcp_syn_fingerprint") as _span:
                    _span.set_attribute("attacker_ip", src_ip)
                    _span.set_attribute("dst_port", dst_port)
                    tcp_fp = _extract_tcp_fingerprint(list(tcp.options or []))

                    ipid_buf = self._ipid_samples.setdefault(
                        src_ip, deque(maxlen=self._SEQ_SAMPLE_SIZE)
                    )
                    ipid_buf.append(int(ip.id))
                    ipid_class = classify_sequence(list(ipid_buf))

                    isn_buf = self._isn_samples.setdefault(
                        src_ip, deque(maxlen=self._SEQ_SAMPLE_SIZE)
                    )
                    isn_buf.append(int(tcp.seq))
                    isn_class = classify_sequence(list(isn_buf))
                    os_label = guess_os(
                        ttl=ip.ttl,
                        window=int(tcp.window),
                        mss=tcp_fp["mss"],
                        wscale=tcp_fp["wscale"],
                        options_sig=tcp_fp["options_sig"],
                    )
                    _span.set_attribute("os_guess", os_label)
                    target_node = self._ip_to_decky[dst_ip]
                    self._log(
                        target_node,
                        "tcp_syn_fingerprint",
                        src_ip=src_ip,
                        src_port=str(src_port),
                        dst_ip=dst_ip,
                        dst_port=str(dst_port),
                        ttl=str(ip.ttl),
                        initial_ttl=str(initial_ttl(ip.ttl)),
                        hop_distance=str(hop_distance(ip.ttl)),
                        window=str(int(tcp.window)),
                        mss=str(tcp_fp["mss"]),
                        wscale=("" if tcp_fp["wscale"] is None else str(tcp_fp["wscale"])),
                        options_sig=tcp_fp["options_sig"],
                        has_sack=str(tcp_fp["sack_ok"]).lower(),
                        has_timestamps=str(tcp_fp["has_timestamps"]).lower(),
                        tos=str(int(getattr(ip, "tos", 0))),
                        dscp=str((int(getattr(ip, "tos", 0)) >> 2) & 0x3F),
                        ecn=str(int(getattr(ip, "tos", 0)) & 0x3),
                        ipid_class=ipid_class,
                        ipid_samples=str(len(ipid_buf)),
                        isn_class=isn_class,
                        isn_samples=str(len(isn_buf)),
                        os_guess=os_label,
                    )

        elif flags & _TCP_SYN and flags & _TCP_ACK:
            rev_key = (dst_ip, dst_port, src_ip, src_port)
            syn_data = self._tcp_syn.pop(rev_key, None)
            if syn_data:
                rtt_ms = round((now - syn_data["time"]) * 1000, 2)
                self._tcp_rtt[rev_key] = {
                    "rtt_ms": rtt_ms,
                    "client_ttl": syn_data["ttl"],
                }

        # Flush flow on FIN/RST (terminal packets).
        if flags & (_TCP_FIN | _TCP_RST):
            decky = self._ip_to_decky.get(flow_key[2])
            if decky:
                self._flush_flow(flow_key, decky)

        payload = bytes(tcp.payload)
        if not payload:
            return

        # SSH client banner (RFC 4253 §4.2): attacker→decky TCP/22, first
        # application-data segment of the flow. Emit once per flow.
        if (
            dst_port == 22
            and dst_ip in self._ip_to_decky
            and direction_forward
        ):
            flow = self._flows.get(flow_key)
            if flow is not None and not flow.get("ssh_banner_seen"):
                banner = _parse_ssh_banner(payload)
                if banner is not None:
                    flow["ssh_banner_seen"] = True
                    target_node = self._ip_to_decky[dst_ip]
                    self._log(
                        target_node,
                        "ssh_client_banner",
                        src_ip=src_ip,
                        src_port=str(src_port),
                        dst_ip=dst_ip,
                        dst_port=str(dst_port),
                        ssh_version=banner,
                    )

        if payload[0] != _TLS_RECORD_HANDSHAKE:
            return

        # ClientHello
        ch = _parse_client_hello(payload)
        if ch is not None:
            _tracer = _get_tracer("sniffer")
            with _tracer.start_as_current_span("sniffer.tls_client_hello") as _span:
                _span.set_attribute("attacker_ip", src_ip)
                _span.set_attribute("dst_port", dst_port)
                self._cleanup_sessions()

                key = (src_ip, src_port, dst_ip, dst_port)
                ja3_str, ja3_hash = _ja3(ch)
                ja4_hash = _ja4(ch)
                resumption = _session_resumption_info(ch)
                rtt_data = _ja4l(key, self._tcp_rtt)

                _span.set_attribute("ja3", ja3_hash)
                _span.set_attribute("ja4", ja4_hash)
                _span.set_attribute("sni", ch["sni"] or "")

                self._sessions[key] = {
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
                self._session_ts[key] = time.monotonic()

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

                # Resolve node for the *destination* (the decky being attacked)
                target_node = self._ip_to_decky.get(dst_ip, node_name)
                self._log(target_node, "tls_client_hello", **log_fields)
            return

        # ServerHello
        sh = _parse_server_hello(payload)
        if sh is not None:
            _tracer = _get_tracer("sniffer")
            with _tracer.start_as_current_span("sniffer.tls_server_hello") as _span:
                _span.set_attribute("attacker_ip", dst_ip)
                rev_key = (dst_ip, dst_port, src_ip, src_port)
                ch_data = self._sessions.pop(rev_key, None)
                self._session_ts.pop(rev_key, None)

                ja3s_str, ja3s_hash = _ja3s(sh)
                ja4s_hash = _ja4s(sh)

                _span.set_attribute("ja3s", ja3s_hash)
                _span.set_attribute("ja4s", ja4s_hash)

                fields: dict[str, Any] = {
                    "src_ip": dst_ip,
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

                rtt_data = self._tcp_rtt.pop(rev_key, None)
                if rtt_data:
                    fields["ja4l_rtt_ms"] = str(rtt_data["rtt_ms"])
                    fields["ja4l_client_ttl"] = str(rtt_data["client_ttl"])

                # Server response — resolve by src_ip (the decky responding)
                target_node = self._ip_to_decky.get(src_ip, node_name)
                self._log(target_node, "tls_session", severity=SEVERITY_WARNING, **fields)
            return

        # Certificate (TLS 1.2 only)
        cert = _parse_certificate(payload)
        if cert is not None:
            _tracer = _get_tracer("sniffer")
            with _tracer.start_as_current_span("sniffer.tls_certificate") as _span:
                _span.set_attribute("subject_cn", cert["subject_cn"])
                _span.set_attribute("self_signed", cert["self_signed"])
                rev_key = (dst_ip, dst_port, src_ip, src_port)
                ch_data = self._sessions.get(rev_key)

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

                target_node = self._ip_to_decky.get(src_ip, node_name)
                self._log(target_node, "tls_certificate", **cert_fields)
