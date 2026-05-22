#!/usr/bin/env python3
"""
DNS server (UDP+TCP/53) — BIND 9.x persona.

event_type values emitted:
  query                  — standard resolution attempt
  fingerprint_probe      — version.bind / hostname.bind / id.server / opcode / flag / qclass probes
  zone_transfer          — AXFR or IXFR (always REFUSED)
  amp_probe              — qtype=ANY or EDNS requestor udp_size > 1232
  tunneling_suspect      — long high-entropy labels or rapid TXT burst from same src
  flood_suspect          — source exceeding QPS threshold within rolling window
  tracking_evicted       — LRU state evicted (signals IP-rotation evasion)
  recon_burst            — same source hit ≥2 distinct high-signal event types within 60s
  malformed_packet       — wire bytes shorter than 12 (no DNS header possible)
  empty_question_section — qdcount=0 (headerless keepalive / scanner probe)
  question_parse_error   — question section could not be decoded
  multi_question         — qdcount>1; only question 0 is answered
"""

import asyncio
import collections
import hashlib
import math
import os
import socket
import struct
import time
from typing import Any, cast

from syslog_bridge import forward_syslog, syslog_line, write_syslog_file
import instance_seed as seed

# ── Config ────────────────────────────────────────────────────────────────────

NODE_NAME      = os.environ.get("NODE_NAME", "ns1")
SERVICE_NAME   = "dns"
LOG_TARGET     = os.environ.get("LOG_TARGET", "")
ZONE_MODE      = os.environ.get("DNS_ZONE_MODE", "auth")
BIND_VERSION   = os.environ.get("DNS_BIND_VERSION", "9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.10")
_NSID_RAW      = os.environ.get("DNS_NSID", "")
_EXTRA_RAW     = os.environ.get("DNS_EXTRA_RECORDS", "")
REAL_RECURSIVE = os.environ.get("DNS_REAL_RECURSIVE", "").lower() in ("1", "true", "yes")

_upstream_raw = os.environ.get("DNS_UPSTREAM", "8.8.8.8:53")
try:
    _up_host, _up_port_str = _upstream_raw.rsplit(":", 1)
    _UPSTREAM_ADDR: tuple[str, int] = (_up_host, int(_up_port_str))
except (ValueError, AttributeError):
    _UPSTREAM_ADDR = ("8.8.8.8", 53)

# ── Zone generation ───────────────────────────────────────────────────────────

_CORP_NAMES    = ["nexus", "apex", "vantage", "summit", "meridian", "vector",
                  "axiom", "helios", "stratos", "cortex", "vertex", "praxis"]
_CORP_SUFFIXES = ["corp", "systems", "tech", "group", "labs", "net"]
_TLDS          = ["local", "internal", "corp", "lan"]


def _generate_domain() -> str:
    custom = os.environ.get("DNS_DOMAIN", "").strip()
    if custom:
        return custom.rstrip(".") + "."
    name   = seed.pick(_CORP_NAMES)
    suffix = seed.pick(_CORP_SUFFIXES)
    tld    = seed.pick(_TLDS)
    return f"{name}-{suffix}.{tld}."


DOMAIN      = _generate_domain()
DOMAIN_BARE = DOMAIN.rstrip(".")
NSID        = _NSID_RAW if _NSID_RAW else seed.instance_uuid("nsid")[:16]

_SOA_SERIAL = int(seed.instance_hex(4, "soa-serial"), 16) % 99 + 2020010101
NS1         = f"ns1.{DOMAIN_BARE}."
NS2         = f"ns2.{DOMAIN_BARE}."


def _fake_ip(label: str = "") -> str:
    h = int(seed.instance_hex(3, f"ip:{label}"), 16)
    return f"10.{(h >> 16) & 0xFF}.{(h >> 8) & 0xFF}.{h & 0xFF}"


def _fake_ipv6(label: str = "") -> str:
    """Deterministic ULA IPv6 address (fd00::/8) for in-zone names."""
    raw = bytes.fromhex(seed.instance_hex(15, f"aaaa:{label}"))
    addr = b"\xfd" + raw  # fd + 15 bytes = 16 bytes total, guaranteed fd::/8
    return socket.inet_ntop(socket.AF_INET6, addr)


ZONE_IP  = _fake_ip("zone")
_NS2_IP  = _fake_ip("ns2")
ZONE_IPV6 = _fake_ipv6("zone")
_NS2_IPV6 = _fake_ipv6("ns2")

# Parse extra_records: one per line, "<name> <TYPE> <value>"
_EXTRA_RECORDS: list[tuple[str, str, str]] = []
for _line in _EXTRA_RAW.splitlines():
    _parts = _line.strip().split(None, 2)
    if len(_parts) == 3:
        _ename, _etype, _eval = _parts[0], _parts[1].upper(), _parts[2]
        if _etype == "AAAA":
            try:
                socket.inet_pton(socket.AF_INET6, _eval)
                _EXTRA_RECORDS.append((_ename, _etype, _eval))
            except OSError:
                pass
        else:
            _EXTRA_RECORDS.append((_ename, _etype, _eval))

# ── DNS wire constants ────────────────────────────────────────────────────────

TYPE_A    = 1
TYPE_NS   = 2
TYPE_SOA  = 6
TYPE_MX   = 15
TYPE_TXT  = 16
TYPE_AAAA = 28
TYPE_OPT  = 41
TYPE_IXFR = 251
TYPE_AXFR = 252
TYPE_ANY  = 255

CLASS_IN  = 1
CLASS_CH  = 3
CLASS_ANY = 255

RCODE_NOERROR  = 0
RCODE_FORMERR  = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP   = 4
RCODE_REFUSED  = 5

_TYPE_NAMES = {
    TYPE_A: "A", TYPE_NS: "NS", TYPE_SOA: "SOA", TYPE_MX: "MX",
    TYPE_TXT: "TXT", TYPE_AAAA: "AAAA", TYPE_IXFR: "IXFR",
    TYPE_AXFR: "AXFR", TYPE_OPT: "OPT", TYPE_ANY: "ANY",
}
_CLASS_NAMES = {CLASS_IN: "IN", CLASS_CH: "CH", CLASS_ANY: "ANY"}

# ── Wire codec ────────────────────────────────────────────────────────────────

def _encode_name(fqdn: str) -> bytes:
    """Encode a DNS name to wire format (no compression)."""
    if not fqdn or fqdn == ".":
        return b"\x00"
    out = b""
    for label in fqdn.rstrip(".").split("."):
        enc = label.encode("ascii", errors="replace")
        out += bytes([len(enc)]) + enc
    return out + b"\x00"


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name supporting RFC 1035 pointer compression."""
    labels: list[str] = []
    next_offset = -1
    jumps = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            if next_offset < 0:
                next_offset = offset + 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated pointer")
            if next_offset < 0:
                next_offset = offset + 2
            jumps += 1
            if jumps > 10:
                raise ValueError("compression loop")
            offset = ((length & 0x3F) << 8) | data[offset + 1]
        else:
            offset += 1
            if offset + length > len(data):
                raise ValueError("truncated label")
            labels.append(
                data[offset:offset + length].decode("ascii", errors="replace").lower()
            )
            offset += length
    name = ".".join(labels) + "." if labels else "."
    return name, next_offset


def _rr(name: str, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
    name_enc = _encode_name(name)
    return name_enc + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def _rdata_A(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def _rdata_AAAA(ip6: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, ip6)


def _rdata_NS(ns: str) -> bytes:
    return _encode_name(ns)


def _rdata_TXT(text: str) -> bytes:
    enc = text.encode("ascii", errors="replace")[:255]
    return bytes([len(enc)]) + enc


def _rdata_MX(priority: int, exchange: str) -> bytes:
    return struct.pack(">H", priority) + _encode_name(exchange)


def _rdata_SOA(
    mname: str, rname: str,
    serial: int, refresh: int, retry: int, expire: int, minimum: int,
) -> bytes:
    return (
        _encode_name(mname)
        + _encode_name(rname)
        + struct.pack(">IIIII", serial, refresh, retry, expire, minimum)
    )


def _build_header(
    qid: int, flags: int,
    qdcount: int, ancount: int, nscount: int, arcount: int,
) -> bytes:
    return struct.pack(">HHHHHH", qid, flags, qdcount, ancount, nscount, arcount)


def _flags_response(
    rd: bool = False, ra: bool = False, aa: bool = False, rcode: int = 0,
) -> int:
    f = 0x8000  # QR=1
    if aa:
        f |= 0x0400
    if rd:
        f |= 0x0100
    if ra:
        f |= 0x0080
    f |= (rcode & 0x0F)
    return f


def _parse_question(data: bytes, offset: int) -> tuple[str, int, int, int]:
    """Return (qname, qtype, qclass, next_offset)."""
    qname, offset = _decode_name(data, offset)
    if offset + 4 > len(data):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack_from(">HH", data, offset)
    return qname, qtype, qclass, offset + 4


def _parse_edns_size(data: bytes, qdcount: int, ancount: int, nscount: int, arcount: int) -> int | None:
    """Walk to the additional section; return requestor UDP size if OPT found."""
    if arcount == 0:
        return None
    offset = 12
    try:
        for _ in range(qdcount):
            _, offset = _decode_name(data, offset)
            offset += 4
        for _ in range(ancount + nscount):
            _, offset = _decode_name(data, offset)
            if offset + 10 > len(data):
                return None
            rdlen = struct.unpack_from(">H", data, offset + 8)[0]
            offset += 10 + rdlen
        for _ in range(arcount):
            if offset >= len(data):
                return None
            if data[offset] == 0:
                # Root label — candidate OPT record
                if offset + 11 > len(data):
                    return None
                rtype = struct.unpack_from(">H", data, offset + 1)[0]
                if rtype == TYPE_OPT:
                    udp_size = struct.unpack_from(">H", data, offset + 3)[0]
                    return udp_size
            _, offset = _decode_name(data, offset)
            if offset + 10 > len(data):
                return None
            rdlen = struct.unpack_from(">H", data, offset + 8)[0]
            offset += 10 + rdlen
    except Exception:
        pass
    return None

# ── Logging ───────────────────────────────────────────────────────────────────

def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)

# ── Tunables ──────────────────────────────────────────────────────────────────

# Tunneling heuristic
_SHANNON_THRESHOLD   = 4.0
_LABEL_LEN_THRESHOLD = 30
_TXT_BURST_WINDOW    = 10.0   # seconds
_TXT_BURST_COUNT     = 5
_MAX_TRACKED_SRCS    = 1000

# Flood detection
_QPS_WINDOW_SEC      = 10.0
_FLOOD_THRESHOLD     = 50
_FLOOD_COOLDOWN_SEC  = 30.0

# Recon burst
_RECON_WINDOW_SEC         = 60.0
_RECON_DISTINCT_THRESHOLD = 2
_RECON_COOLDOWN_SEC       = 120.0
_RECON_SIGNAL_TYPES       = frozenset({"fingerprint_probe", "zone_transfer", "amp_probe"})

# Eviction telemetry
_EVICT_EVENT_EVERY = 100

# Global upstream forwarding budget
_FORWARD_BUDGET_MAX = int(os.environ.get("DNS_FORWARD_BUDGET", "50"))
_FORWARD_BUDGET_WIN = float(os.environ.get("DNS_FORWARD_WINDOW", "1.0"))

# ── Per-src state ─────────────────────────────────────────────────────────────

# Tunneling: src_ip -> deque of recent TXT timestamps
_txt_times: collections.OrderedDict[str, collections.deque] = collections.OrderedDict()

# Flood: src_ip -> deque of recent query timestamps
_qps_window: collections.OrderedDict[str, collections.deque] = collections.OrderedDict()

# Flood cooldown: src_ip -> last flood_suspect emit time
_flood_cooldown: dict[str, float] = {}

# Recon: src_ip -> {event_type: last_seen_monotonic}
_recon_window: collections.OrderedDict[str, dict[str, float]] = collections.OrderedDict()

# Recon cooldown: src_ip -> last recon_burst emit time
_recon_cooldown: dict[str, float] = {}

_evictions_total = 0

# Global forward budget: timestamps of recent upstream calls
_forward_timestamps: collections.deque[float] = collections.deque()


def _can_forward() -> bool:
    """Return True and consume one budget slot if under the global forward limit."""
    now = time.monotonic()
    _forward_timestamps.append(now)
    while _forward_timestamps[0] < now - _FORWARD_BUDGET_WIN:
        _forward_timestamps.popleft()
    return len(_forward_timestamps) <= _FORWARD_BUDGET_MAX


def _note_eviction(tracker_name: str) -> None:
    global _evictions_total
    _evictions_total += 1
    if _evictions_total % _EVICT_EVENT_EVERY == 0:
        _log(
            "tracking_evicted",
            evictions_total=_evictions_total,
            capacity=_MAX_TRACKED_SRCS,
            tracker_name=tracker_name,
        )


def _track_lru(table: collections.OrderedDict, key: str, tracker_name: str) -> None:
    """Touch key to MRU end; evict LRU entries if over capacity."""
    if key in table:
        table.move_to_end(key)
    while len(table) > _MAX_TRACKED_SRCS:
        table.popitem(last=False)
        _note_eviction(tracker_name)

# ── Tunneling heuristic ───────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _is_tunneling(qname: str, qtype: int, src: str) -> bool:
    for label in qname.rstrip(".").split("."):
        if len(label) >= _LABEL_LEN_THRESHOLD and _shannon_entropy(label) > _SHANNON_THRESHOLD:
            return True
    if qtype == TYPE_TXT:
        now = time.monotonic()
        if src not in _txt_times:
            _txt_times[src] = collections.deque()
        _track_lru(_txt_times, src, "txt_times")
        q = _txt_times[src]
        q.append(now)
        while q and now - q[0] > _TXT_BURST_WINDOW:
            q.popleft()
        if len(q) >= _TXT_BURST_COUNT:
            return True
    return False

# ── Flood detection ───────────────────────────────────────────────────────────

def _check_flood(src: str, qtype_name: str) -> bool:
    """Return True (and emit flood_suspect once per cooldown) if src is flooding."""
    now = time.monotonic()
    if src not in _qps_window:
        _qps_window[src] = collections.deque()
    _track_lru(_qps_window, src, "qps_window")
    q = _qps_window[src]
    q.append(now)
    while q and now - q[0] > _QPS_WINDOW_SEC:
        q.popleft()
    if len(q) >= _FLOOD_THRESHOLD:
        last = _flood_cooldown.get(src, 0.0)
        if now - last >= _FLOOD_COOLDOWN_SEC:
            _flood_cooldown[src] = now
            _log(
                "flood_suspect",
                src=src,
                qps=len(q),
                window_sec=_QPS_WINDOW_SEC,
                sample_qtype=qtype_name,
            )
            return True
    return False

# ── Recon burst aggregation ───────────────────────────────────────────────────

def _note_recon_event(src: str, event_type: str) -> None:
    """Record a high-signal event; emit recon_burst if threshold met."""
    if event_type not in _RECON_SIGNAL_TYPES:
        return
    now = time.monotonic()
    if src not in _recon_window:
        _recon_window[src] = {}
    _track_lru(_recon_window, src, "recon_window")
    _recon_window[src][event_type] = now
    # Prune events older than window
    stale = [k for k, t in _recon_window[src].items() if now - t > _RECON_WINDOW_SEC]
    for k in stale:
        del _recon_window[src][k]
    active = _recon_window[src]
    if len(active) >= _RECON_DISTINCT_THRESHOLD:
        last = _recon_cooldown.get(src, 0.0)
        if now - last >= _RECON_COOLDOWN_SEC:
            _recon_cooldown[src] = now
            seq = sorted(
                [(et, round(now - t, 1)) for et, t in active.items()],
                key=lambda x: x[1],
            )
            _log(
                "recon_burst",
                src=src,
                distinct_types=len(active),
                window_sec=_RECON_WINDOW_SEC,
                sequence=str(seq),
            )

# ── Response builders ─────────────────────────────────────────────────────────

def _refused_response(qid: int, rd: bool, qname: str, qtype: int, qclass: int) -> bytes:
    flags = _flags_response(rd=rd, rcode=RCODE_REFUSED)
    q = _encode_name(qname) + struct.pack(">HH", qtype, qclass)
    return _build_header(qid, flags, 1, 0, 0, 0) + q


def _soa_rr(ttl: int = 300) -> bytes:
    rdata = _rdata_SOA(
        NS1, f"hostmaster.{DOMAIN_BARE}.",
        _SOA_SERIAL, 3600, 900, 604800, 300,
    )
    return _rr(DOMAIN, TYPE_SOA, CLASS_IN, ttl, rdata)


def _nxdomain_response(qid: int, rd: bool, qname: str, qtype: int, qclass: int) -> bytes:
    flags = _flags_response(rd=rd, aa=True, rcode=RCODE_NXDOMAIN)
    q = _encode_name(qname) + struct.pack(">HH", qtype, qclass)
    auth = _soa_rr(300)
    return _build_header(qid, flags, 1, 0, 1, 0) + q + auth


def _chaos_txt_response(qid: int, rd: bool, qname: str, text: str) -> bytes:
    flags = _flags_response(rd=rd, aa=True, rcode=RCODE_NOERROR)
    q = _encode_name(qname) + struct.pack(">HH", TYPE_TXT, CLASS_CH)
    answer = _rr(qname, TYPE_TXT, CLASS_CH, 0, _rdata_TXT(text))
    return _build_header(qid, flags, 1, 1, 0, 0) + q + answer


def _auth_response(qid: int, rd: bool, qname: str, qtype: int) -> bytes:
    """Authoritative IN response for the generated zone."""
    qname_bare = qname.rstrip(".")
    in_zone = (
        qname_bare == DOMAIN_BARE
        or qname_bare.endswith("." + DOMAIN_BARE)
    )

    # Out-of-zone handling
    if not in_zone:
        if ZONE_MODE == "open":
            # Sinkhole A: deterministic 127.0.0.x
            h = int(hashlib.sha256(qname.encode()).hexdigest()[:2], 16) or 1
            ip = f"127.0.0.{h}"
            flags = _flags_response(rd=rd, aa=False, rcode=RCODE_NOERROR)
            q = _encode_name(qname) + struct.pack(">HH", qtype, CLASS_IN)
            ans = _rr(qname, TYPE_A, CLASS_IN, 30, _rdata_A(ip))
            return _build_header(qid, flags, 1, 1, 0, 0) + q + ans
        if ZONE_MODE == "recursive":
            h = int(hashlib.sha256(qname.encode()).hexdigest()[:2], 16) or 1
            ip = f"127.0.0.{h}"
            flags = _flags_response(rd=rd, aa=False, ra=True, rcode=RCODE_NOERROR)
            q = _encode_name(qname) + struct.pack(">HH", qtype, CLASS_IN)
            ans = _rr(qname, TYPE_A, CLASS_IN, 30, _rdata_A(ip))
            return _build_header(qid, flags, 1, 1, 0, 0) + q + ans
        return _refused_response(qid, rd, qname, qtype, CLASS_IN)

    flags = _flags_response(rd=rd, aa=True, rcode=RCODE_NOERROR)
    q = _encode_name(qname) + struct.pack(">HH", qtype, CLASS_IN)
    answers: list[bytes] = []
    authority: list[bytes] = []

    # Built-in zone records
    _well_known = {
        DOMAIN_BARE,
        f"www.{DOMAIN_BARE}",
        f"mail.{DOMAIN_BARE}",
        f"ns1.{DOMAIN_BARE}",
        f"ns2.{DOMAIN_BARE}",
    }

    if qtype in (TYPE_A, TYPE_ANY):
        ip_map = {
            DOMAIN_BARE:           ZONE_IP,
            f"www.{DOMAIN_BARE}":  ZONE_IP,
            f"mail.{DOMAIN_BARE}": _fake_ip("mail"),
            f"ns1.{DOMAIN_BARE}":  ZONE_IP,
            f"ns2.{DOMAIN_BARE}":  _NS2_IP,
        }
        if qname_bare in ip_map:
            answers.append(_rr(qname, TYPE_A, CLASS_IN, 300, _rdata_A(ip_map[qname_bare])))

    if qtype in (TYPE_AAAA, TYPE_ANY):
        ipv6_map = {
            DOMAIN_BARE:           ZONE_IPV6,
            f"www.{DOMAIN_BARE}":  ZONE_IPV6,
            f"mail.{DOMAIN_BARE}": _fake_ipv6("mail"),
            f"ns1.{DOMAIN_BARE}":  ZONE_IPV6,
            f"ns2.{DOMAIN_BARE}":  _NS2_IPV6,
        }
        if qname_bare in ipv6_map:
            answers.append(_rr(qname, TYPE_AAAA, CLASS_IN, 300, _rdata_AAAA(ipv6_map[qname_bare])))

    if qtype in (TYPE_NS, TYPE_ANY) and qname_bare == DOMAIN_BARE:
        answers.append(_rr(DOMAIN, TYPE_NS, CLASS_IN, 3600, _rdata_NS(NS1)))
        answers.append(_rr(DOMAIN, TYPE_NS, CLASS_IN, 3600, _rdata_NS(NS2)))

    if qtype in (TYPE_SOA, TYPE_ANY) and qname_bare == DOMAIN_BARE:
        answers.append(_soa_rr())

    if qtype in (TYPE_MX, TYPE_ANY) and qname_bare == DOMAIN_BARE:
        answers.append(_rr(DOMAIN, TYPE_MX, CLASS_IN, 3600, _rdata_MX(10, f"mail.{DOMAIN_BARE}.")))

    if qtype in (TYPE_TXT, TYPE_ANY) and qname_bare == DOMAIN_BARE:
        answers.append(_rr(DOMAIN, TYPE_TXT, CLASS_IN, 3600, _rdata_TXT("v=spf1 a mx ~all")))

    # User-supplied extra records
    for ername, ertype, erval in _EXTRA_RECORDS:
        er_fqdn = ername if ername.endswith(".") else f"{ername}.{DOMAIN_BARE}."
        er_bare = er_fqdn.rstrip(".")
        if qname_bare != er_bare:
            continue
        if ertype == "A" and qtype in (TYPE_A, TYPE_ANY):
            answers.append(_rr(er_fqdn, TYPE_A, CLASS_IN, 300, _rdata_A(erval)))
        elif ertype == "AAAA" and qtype in (TYPE_AAAA, TYPE_ANY):
            answers.append(_rr(er_fqdn, TYPE_AAAA, CLASS_IN, 300, _rdata_AAAA(erval)))
        elif ertype == "TXT" and qtype in (TYPE_TXT, TYPE_ANY):
            answers.append(_rr(er_fqdn, TYPE_TXT, CLASS_IN, 300, _rdata_TXT(erval)))
        elif ertype == "CNAME" and qtype in (TYPE_A, TYPE_ANY):
            answers.append(_rr(er_fqdn, 5, CLASS_IN, 300, _encode_name(erval)))

    if not answers:
        if qname_bare not in _well_known:
            return _nxdomain_response(qid, rd, qname, qtype, CLASS_IN)
        # Name exists but no records of this type — NOERROR + SOA in authority
        authority.append(_soa_rr())

    answer_bytes  = b"".join(answers)
    auth_bytes    = b"".join(authority)
    return (
        _build_header(qid, flags, 1, len(answers), len(authority), 0)
        + q + answer_bytes + auth_bytes
    )

# ── Real recursive forwarding ─────────────────────────────────────────────────

def _is_upstream_candidate(data: bytes) -> bool:
    """True when the query should be forwarded to the upstream resolver."""
    if not REAL_RECURSIVE or ZONE_MODE != "recursive":
        return False
    if len(data) < 12:
        return False
    try:
        qdcount = struct.unpack_from(">H", data, 4)[0]
        if qdcount == 0:
            return False
        qname, qtype, qclass, _ = _parse_question(data, 12)
        if qclass != CLASS_IN or qtype in (TYPE_AXFR, TYPE_IXFR):
            return False
        qname_bare = qname.rstrip(".")
        in_zone = qname_bare == DOMAIN_BARE or qname_bare.endswith("." + DOMAIN_BARE)
        return not in_zone
    except Exception:
        return False


async def _forward_upstream(data: bytes) -> bytes | None:
    """Send raw query bytes to the upstream resolver; return raw response or None."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, _UPSTREAM_ADDR)
        await loop.sock_sendall(sock, data)
        response = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=3.0)
        return response if len(response) >= 12 else None
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


async def _dispatch(data: bytes, src_ip: str, src_port: int, transport: str) -> bytes | None:
    """Async dispatcher: runs sync _handle (logging + detection), then overlays
    upstream forwarding for real-recursive out-of-zone queries."""
    sinkhole = _handle(data, src_ip, src_port, transport)
    if _is_upstream_candidate(data) and _can_forward():
        upstream = await _forward_upstream(data)
        if upstream is not None:
            return upstream
    return sinkhole

# ── Request dispatcher ────────────────────────────────────────────────────────

def _handle(data: bytes, src_ip: str, src_port: int, transport: str) -> bytes | None:
    """Parse one DNS request and return the response wire bytes, emitting events."""
    if len(data) < 12:
        _log("malformed_packet", severity=5, src=src_ip, src_port=src_port,
             transport=transport, length=len(data))
        return None
    qid, flags_in, qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHHHH", data, 0)
    if qdcount == 0:
        _log("empty_question_section", severity=5, src=src_ip, src_port=src_port,
             transport=transport, qid=qid)
        return None
    rd = bool(flags_in & 0x0100)

    try:
        qname, qtype, qclass, _ = _parse_question(data, 12)
    except ValueError as exc:
        _log("question_parse_error", severity=5, src=src_ip, src_port=src_port,
             transport=transport, reason=str(exc)[:64])
        return None

    edns_size = _parse_edns_size(data, qdcount, ancount, nscount, arcount)

    qtype_name  = _TYPE_NAMES.get(qtype, str(qtype))
    qclass_name = _CLASS_NAMES.get(qclass, str(qclass))

    # Flood check runs on every packet (including CHAOS / transfer probes)
    _check_flood(src_ip, qtype_name)

    # ── Zone transfer ──────────────────────────────────────────────────────
    if qtype in (TYPE_AXFR, TYPE_IXFR):
        _log(
            "zone_transfer",
            src=src_ip, src_port=src_port, transport=transport,
            qname=qname.rstrip("."), qtype=qtype_name, qclass=qclass_name,
            zone=DOMAIN,
        )
        _note_recon_event(src_ip, "zone_transfer")
        return _refused_response(qid, rd, qname, qtype, qclass)

    # ── CHAOS fingerprinting ───────────────────────────────────────────────
    if qclass == CLASS_CH and qtype == TYPE_TXT:
        probe_map = {
            "version.bind.":  BIND_VERSION,
            "hostname.bind.": NODE_NAME,
            "id.server.":     NSID,
        }
        answer_text = probe_map.get(qname, "")
        _log(
            "fingerprint_probe",
            src=src_ip, src_port=src_port, transport=transport,
            probe=qname.rstrip("."), response=answer_text,
        )
        _note_recon_event(src_ip, "fingerprint_probe")
        if answer_text:
            return _chaos_txt_response(qid, rd, qname, answer_text)
        return _refused_response(qid, rd, qname, qtype, qclass)

    # ── Classify amp / tunneling ───────────────────────────────────────────
    is_amp    = qtype == TYPE_ANY or (edns_size is not None and edns_size > 1232)
    is_tunnel = _is_tunneling(qname, qtype, src_ip)

    response = _auth_response(qid, rd, qname, qtype)

    # Emit events — tunneling and amp each get their own event; plain queries
    # only get logged when neither flag is set.
    base: dict[str, Any] = dict(
        src=src_ip, src_port=src_port, transport=transport,
        qname=qname.rstrip("."), qtype=qtype_name, qclass=qclass_name,
        edns_size=edns_size or 0, recursion_desired=rd,
    )
    if is_tunnel:
        _log("tunneling_suspect", **base)
    if is_amp:
        _log("amp_probe", **base)
        _note_recon_event(src_ip, "amp_probe")
    if not is_tunnel and not is_amp:
        _log("query", **base)

    return response

# ── UDP transport ─────────────────────────────────────────────────────────────

class _DNSUDPProtocol(asyncio.DatagramProtocol):
    _transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        asyncio.ensure_future(self._handle_datagram(data, addr))

    async def _handle_datagram(self, data: bytes, addr: tuple) -> None:
        try:
            response = await _dispatch(data, addr[0], addr[1], "udp")
            if response and self._transport:
                self._transport.sendto(response, addr)
        except Exception:
            pass

    def error_received(self, exc: Exception) -> None:
        pass

# ── TCP transport ─────────────────────────────────────────────────────────────

async def _tcp_session(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """One DNS-over-TCP session; RFC 1035 §4.2.2 length-prefixed framing."""
    peername = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    src_ip, src_port = peername[0], peername[1]
    try:
        while True:
            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
            msg_len = struct.unpack(">H", length_bytes)[0]
            if msg_len == 0:
                break
            data = await asyncio.wait_for(reader.readexactly(msg_len), timeout=10.0)
            response = await _dispatch(data, src_ip, src_port, "tcp")
            if response:
                writer.write(struct.pack(">H", len(response)) + response)
                await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionResetError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    _log("startup", msg=f"DNS server: zone={DOMAIN} mode={ZONE_MODE} version={BIND_VERSION}")
    loop = asyncio.get_running_loop()
    udp_transport, _ = await loop.create_datagram_endpoint(
        _DNSUDPProtocol, local_addr=("0.0.0.0", 53)  # nosec B104
    )
    tcp_server = await asyncio.start_server(
        _tcp_session, "0.0.0.0", 53  # nosec B104
    )
    try:
        await asyncio.sleep(float("inf"))
    finally:
        udp_transport.close()
        tcp_server.close()


if __name__ == "__main__":
    asyncio.run(main())
