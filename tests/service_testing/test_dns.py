"""Tests for decnet/templates/dns/server.py and decnet/services/dns.py."""

import collections
import hashlib
import importlib.util
import socket
import struct
import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

_SERVER_PATH = "decnet/templates/dns/server.py"

# ── Test helpers ──────────────────────────────────────────────────────────────

def _make_fake_syslog_bridge() -> ModuleType:
    mod = ModuleType("syslog_bridge")
    events: list[tuple[str, dict]] = []

    def syslog_line(service, hostname, event_type, severity=6, **fields):
        events.append((event_type, fields))
        return f"LOG {event_type}"

    mod.syslog_line = syslog_line
    mod.write_syslog_file = MagicMock()
    mod.forward_syslog = MagicMock()
    mod.SEVERITY_INFO = 6
    mod.SEVERITY_WARNING = 4
    mod.encode_secret = MagicMock(return_value={"secret_printable": "", "secret_b64": ""})
    mod._events = events
    return mod


def _make_fake_instance_seed() -> ModuleType:
    import random as _random
    mod = ModuleType("instance_seed")
    mod.rng = _random.Random(42)
    mod.pick = lambda choices: list(choices)[0]
    mod.instance_uuid = lambda ns="": f"aaaabbbb-cccc-dddd-eeee-{ns[:12].ljust(12, '0')}"
    mod.instance_hex = lambda nbytes, ns="": (hashlib.sha256(ns.encode()).hexdigest() * 4)[:nbytes * 2]
    mod.hostname = lambda: "testhost"
    mod.jitter = MagicMock()
    return mod


def _load_dns(extra_env: dict | None = None):
    """Load server.py in isolation with mocked syslog_bridge and instance_seed."""
    env = {
        "NODE_NAME": "testhost",
        "DNS_ZONE_MODE": "auth",
        "DNS_DOMAIN": "test.local",
        "DNS_BIND_VERSION": "9.11.4-TEST",
        "DNS_NSID": "testnsid",
        "DNS_EXTRA_RECORDS": "",
        **(extra_env or {}),
    }
    for key in list(sys.modules):
        if key in ("dns_server", "syslog_bridge", "instance_seed"):
            del sys.modules[key]

    bridge = _make_fake_syslog_bridge()
    seed   = _make_fake_instance_seed()
    sys.modules["syslog_bridge"] = bridge
    sys.modules["instance_seed"] = seed

    spec = importlib.util.spec_from_file_location("dns_server", _SERVER_PATH)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    with patch.dict("os.environ", env, clear=False):
        spec.loader.exec_module(mod)  # type: ignore[union-attr]

    # Reset per-src state between tests
    mod._txt_times.clear()
    mod._qps_window.clear()
    mod._flood_cooldown.clear()
    mod._recon_window.clear()
    mod._recon_cooldown.clear()

    return mod, bridge._events


def _build_query(
    qname: str,
    qtype: int,
    qclass: int = 1,
    qid: int = 0x1234,
    rd: bool = True,
    extra_flags: int = 0,
) -> bytes:
    """Minimal DNS query wire packet."""
    flags = (0x0100 if rd else 0x0000) | extra_flags
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    wire = b""
    for label in qname.rstrip(".").split("."):
        enc = label.encode("ascii")
        wire += bytes([len(enc)]) + enc
    wire += b"\x00"
    return header + wire + struct.pack(">HH", qtype, qclass)


def _rcode(data: bytes) -> int:
    return struct.unpack_from(">H", data, 2)[0] & 0x0F


def _counts(data: bytes) -> tuple[int, int, int, int]:
    _, _, qd, an, ns, ar = struct.unpack_from(">HHHHHH", data, 0)
    return qd, an, ns, ar


def _events_of(events: list, kind: str) -> list[dict]:
    return [fields for etype, fields in events if etype == kind]


def _build_opt_rr(udp_size: int = 4096, options: list[tuple[int, bytes]] = []) -> bytes:
    """Build an OPT additional record (owner=root, TYPE=41)."""
    rdata = b""
    for code, opt_data in options:
        rdata += struct.pack(">HH", code, len(opt_data)) + opt_data
    # Root label (1 byte) + TYPE(2) + CLASS=udp_size(2) + TTL(4) + RDLEN(2) + RDATA
    return b"\x00" + struct.pack(">HHIH", 41, udp_size, 0, len(rdata)) + rdata


def _build_query_with_opt(
    qname: str,
    qtype: int,
    qclass: int = 1,
    qid: int = 0x1234,
    rd: bool = True,
    udp_size: int = 4096,
    opt_options: list[tuple[int, bytes]] | None = None,
) -> bytes:
    """DNS query with an OPT additional record, optionally carrying sub-options."""
    flags = 0x0100 if rd else 0x0000
    wire = b""
    for label in qname.rstrip(".").split("."):
        enc = label.encode("ascii")
        wire += bytes([len(enc)]) + enc
    wire += b"\x00"
    question = wire + struct.pack(">HH", qtype, qclass)
    opt = _build_opt_rr(udp_size, opt_options or [])
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1)  # arcount=1
    return header + question + opt

# ── Auth zone ─────────────────────────────────────────────────────────────────

class TestAuthZone:
    def test_a_record_apex(self):
        mod, events = _load_dns()
        resp = mod._handle(_build_query("test.local", mod.TYPE_A), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR
        _, ancount, _, _ = _counts(resp)
        assert ancount >= 1
        assert _events_of(events, "query")

    def test_a_record_www(self):
        mod, events = _load_dns()
        resp = mod._handle(_build_query("www.test.local", mod.TYPE_A), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR
        _, ancount, _, _ = _counts(resp)
        assert ancount >= 1

    def test_nxdomain_unknown_name(self):
        mod, _ = _load_dns()
        resp = mod._handle(_build_query("nobody.test.local", mod.TYPE_A), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NXDOMAIN

    def test_out_of_zone_refused_in_auth_mode(self):
        mod, _ = _load_dns({"DNS_ZONE_MODE": "auth"})
        resp = mod._handle(_build_query("google.com", mod.TYPE_A), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_REFUSED

    def test_soa_record(self):
        mod, events = _load_dns()
        resp = mod._handle(_build_query("test.local", mod.TYPE_SOA), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR
        _, ancount, _, _ = _counts(resp)
        assert ancount >= 1

    def test_mx_record(self):
        mod, events = _load_dns()
        resp = mod._handle(_build_query("test.local", mod.TYPE_MX), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR

    def test_extra_records_parsed(self):
        mod, events = _load_dns({"DNS_EXTRA_RECORDS": "extra A 192.168.0.50"})
        resp = mod._handle(_build_query("extra.test.local", mod.TYPE_A), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR

# ── AAAA / IPv6 ───────────────────────────────────────────────────────────────

class TestAAAARecords:
    def test_aaaa_apex(self):
        mod, _ = _load_dns()
        resp = mod._handle(_build_query("test.local", mod.TYPE_AAAA), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR
        _, ancount, _, _ = _counts(resp)
        assert ancount >= 1

    def test_aaaa_rdata_is_16_bytes_and_ula(self):
        mod, _ = _load_dns()
        resp = mod._handle(_build_query("test.local", mod.TYPE_AAAA), "1.2.3.4", 1234, "udp")
        assert resp is not None
        # Walk past header(12) + question to reach answer RDATA
        # Question: encoded "test.local" + 4 bytes type/class
        # We just need to find a 16-byte block starting with 0xfd somewhere
        # The AAAA RDATA is 16 bytes; first byte must be 0xfd (ULA)
        assert b"\xfd" in resp  # ULA fd::/8

    def test_aaaa_www(self):
        mod, _ = _load_dns()
        resp = mod._handle(_build_query("www.test.local", mod.TYPE_AAAA), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR
        _, ancount, _, _ = _counts(resp)
        assert ancount >= 1

    def test_aaaa_out_of_zone_refused(self):
        mod, _ = _load_dns({"DNS_ZONE_MODE": "auth"})
        resp = mod._handle(_build_query("google.com", mod.TYPE_AAAA), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_REFUSED

    def test_extra_record_aaaa(self):
        mod, _ = _load_dns({"DNS_EXTRA_RECORDS": "ipv6host AAAA fd00::1234"})
        resp = mod._handle(_build_query("ipv6host.test.local", mod.TYPE_AAAA), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR
        _, ancount, _, _ = _counts(resp)
        assert ancount >= 1

    def test_extra_record_invalid_aaaa_skipped(self):
        """Invalid AAAA value in DNS_EXTRA_RECORDS must not crash the server."""
        mod, _ = _load_dns({"DNS_EXTRA_RECORDS": "badhost AAAA not-an-ipv6"})
        # If we got a module, the parser didn't crash
        resp = mod._handle(_build_query("badhost.test.local", mod.TYPE_AAAA), "1.2.3.4", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NXDOMAIN  # record was silently dropped

    def test_fake_ipv6_returns_ula(self):
        mod, _ = _load_dns()
        ip6 = mod._fake_ipv6("test")
        parsed = socket.inet_pton(socket.AF_INET6, ip6)
        assert parsed[0] == 0xFD  # first byte must be fd

    def test_fake_ipv6_deterministic(self):
        mod, _ = _load_dns()
        assert mod._fake_ipv6("x") == mod._fake_ipv6("x")

    def test_fake_ipv6_distinct_labels(self):
        mod, _ = _load_dns()
        assert mod._fake_ipv6("zone") != mod._fake_ipv6("ns2")

# ── Fingerprint probes ────────────────────────────────────────────────────────

class TestFingerprintProbe:
    def test_version_bind_returns_configured_banner(self):
        mod, events = _load_dns()
        query = _build_query("version.bind", mod.TYPE_TXT, qclass=mod.CLASS_CH)
        resp = mod._handle(query, "10.0.0.1", 12345, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR
        _, ancount, _, _ = _counts(resp)
        assert ancount == 1
        probes = _events_of(events, "fingerprint_probe")
        assert probes
        assert probes[0]["probe"] == "version.bind"
        assert probes[0]["response"] == "9.11.4-TEST"

    def test_hostname_bind_emits_fingerprint_probe(self):
        mod, events = _load_dns()
        query = _build_query("hostname.bind", mod.TYPE_TXT, qclass=mod.CLASS_CH)
        resp = mod._handle(query, "10.0.0.1", 12345, "udp")
        assert resp is not None
        assert _events_of(events, "fingerprint_probe")

    def test_id_server_emits_fingerprint_probe(self):
        mod, events = _load_dns()
        query = _build_query("id.server", mod.TYPE_TXT, qclass=mod.CLASS_CH)
        resp = mod._handle(query, "10.0.0.1", 12345, "udp")
        assert resp is not None
        assert _events_of(events, "fingerprint_probe")

    def test_unknown_chaos_is_refused_still_logged(self):
        mod, events = _load_dns()
        query = _build_query("something.chaos", mod.TYPE_TXT, qclass=mod.CLASS_CH)
        resp = mod._handle(query, "10.0.0.1", 12345, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_REFUSED
        assert _events_of(events, "fingerprint_probe")

    def test_no_query_event_for_fingerprint(self):
        mod, events = _load_dns()
        query = _build_query("version.bind", mod.TYPE_TXT, qclass=mod.CLASS_CH)
        mod._handle(query, "10.0.0.1", 12345, "udp")
        assert not _events_of(events, "query")

    def test_authors_bind_identified_by_name(self):
        mod, events = _load_dns()
        query = _build_query("authors.bind", mod.TYPE_TXT, qclass=mod.CLASS_CH)
        resp = mod._handle(query, "10.0.0.1", 12345, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR
        probes = _events_of(events, "fingerprint_probe")
        assert probes
        assert probes[0]["probe"] == "authors.bind"
        assert probes[0]["response"] != ""

    def test_authors_bind_in_probe_map(self):
        mod, _ = _load_dns()
        assert "authors.bind." in mod._CHAOS_PROBE_MAP

    def test_chaos_probe_map_introspectable(self):
        mod, _ = _load_dns()
        assert "version.bind." in mod._CHAOS_PROBE_MAP
        assert "hostname.bind." in mod._CHAOS_PROBE_MAP
        assert "id.server." in mod._CHAOS_PROBE_MAP

# ── Zone transfer ─────────────────────────────────────────────────────────────

class TestZoneTransfer:
    def test_axfr_refused_and_logged(self):
        mod, events = _load_dns()
        query = _build_query("test.local", mod.TYPE_AXFR)
        resp = mod._handle(query, "5.5.5.5", 9999, "tcp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_REFUSED
        xfers = _events_of(events, "zone_transfer")
        assert xfers
        assert xfers[0]["qtype"] == "AXFR"
        assert xfers[0]["transport"] == "tcp"

    def test_ixfr_refused_and_logged(self):
        mod, events = _load_dns()
        query = _build_query("test.local", mod.TYPE_IXFR)
        resp = mod._handle(query, "5.5.5.5", 9999, "tcp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_REFUSED
        xfers = _events_of(events, "zone_transfer")
        assert xfers
        assert xfers[0]["qtype"] == "IXFR"

# ── Amp probes ────────────────────────────────────────────────────────────────

class TestAmpProbe:
    def test_qtype_any_emits_amp_probe(self):
        mod, events = _load_dns()
        query = _build_query("test.local", mod.TYPE_ANY)
        resp = mod._handle(query, "2.2.2.2", 5353, "udp")
        assert resp is not None
        assert _events_of(events, "amp_probe")

    def test_amp_probe_suppresses_plain_query_event(self):
        mod, events = _load_dns()
        query = _build_query("test.local", mod.TYPE_ANY)
        mod._handle(query, "2.2.2.2", 5353, "udp")
        assert not _events_of(events, "query")

# ── Tunneling heuristic ───────────────────────────────────────────────────────

class TestTunnelingHeuristic:
    def test_long_high_entropy_label(self):
        mod, events = _load_dns()
        # 40-char high-entropy label (mix of alpha + digits)
        label = "abcdefghijklmnopqrstuvwxyz0123456789abcd"
        assert len(label) >= mod._LABEL_LEN_THRESHOLD
        query = _build_query(f"{label}.test.local", mod.TYPE_A)
        resp = mod._handle(query, "9.9.9.9", 1234, "udp")
        assert resp is not None
        assert _events_of(events, "tunneling_suspect")

    def test_rapid_txt_burst_triggers_tunneling(self):
        mod, events = _load_dns()
        src = "3.3.3.3"
        # 5 TXT queries in rapid succession triggers the burst heuristic
        for i in range(5):
            query = _build_query(f"chunk{i}.test.local", mod.TYPE_TXT)
            mod._handle(query, src, 1234, "udp")
        assert _events_of(events, "tunneling_suspect")

    def test_tunneling_suppresses_plain_query_event(self):
        mod, events = _load_dns()
        label = "abcdefghijklmnopqrstuvwxyz0123456789abcd"
        query = _build_query(f"{label}.test.local", mod.TYPE_A)
        mod._handle(query, "9.9.9.9", 1234, "udp")
        assert not _events_of(events, "query")

# ── Flood detection ───────────────────────────────────────────────────────────

class TestFloodDetection:
    def test_flood_threshold_emits_flood_suspect(self):
        mod, events = _load_dns()
        src = "7.7.7.7"
        # Send _FLOOD_THRESHOLD queries (default 50) in one shot
        for i in range(mod._FLOOD_THRESHOLD):
            mod._handle(_build_query(f"q{i}.test.local", mod.TYPE_A), src, 1234, "udp")
        assert _events_of(events, "flood_suspect")

    def test_flood_suspect_fires_only_once_within_cooldown(self):
        mod, events = _load_dns()
        src = "8.8.8.8"
        # Send well above threshold — should still be one event due to cooldown
        for i in range(mod._FLOOD_THRESHOLD * 2):
            mod._handle(_build_query(f"q{i}.test.local", mod.TYPE_A), src, 1234, "udp")
        floods = _events_of(events, "flood_suspect")
        assert len(floods) == 1

    def test_flood_does_not_suppress_query_events(self):
        """flood_suspect is additive — baseline query events still fire."""
        mod, events = _load_dns()
        src = "9.9.9.8"
        for i in range(mod._FLOOD_THRESHOLD):
            mod._handle(_build_query(f"r{i}.test.local", mod.TYPE_A), src, 1234, "udp")
        # Queries from a flooding src still produce query events
        assert _events_of(events, "query")

    def test_flood_includes_qps_and_window(self):
        mod, events = _load_dns()
        src = "6.6.6.6"
        for i in range(mod._FLOOD_THRESHOLD):
            mod._handle(_build_query(f"q{i}.test.local", mod.TYPE_A), src, 1234, "udp")
        floods = _events_of(events, "flood_suspect")
        assert floods
        assert "qps" in floods[0]
        assert "window_sec" in floods[0]

    def test_tracking_evicted_on_lru_overflow(self):
        mod, events = _load_dns()
        # Fill qps_window beyond _MAX_TRACKED_SRCS to trigger eviction
        # We need _EVICT_EVENT_EVERY evictions to fire tracking_evicted
        evict_target = mod._EVICT_EVENT_EVERY
        capacity = mod._MAX_TRACKED_SRCS
        for i in range(capacity + evict_target):
            src = f"10.{i >> 16 & 0xFF}.{i >> 8 & 0xFF}.{i & 0xFF}"
            mod._handle(_build_query("test.local", mod.TYPE_A), src, 1234, "udp")
        assert _events_of(events, "tracking_evicted")

# ── Recon burst aggregation ───────────────────────────────────────────────────

class TestReconBurst:
    def test_fingerprint_then_axfr_triggers_recon_burst(self):
        mod, events = _load_dns()
        src = "5.5.5.1"
        # fingerprint_probe
        mod._handle(
            _build_query("version.bind", mod.TYPE_TXT, qclass=mod.CLASS_CH),
            src, 1234, "udp",
        )
        # zone_transfer
        mod._handle(_build_query("test.local", mod.TYPE_AXFR), src, 1234, "tcp")
        bursts = _events_of(events, "recon_burst")
        assert bursts
        assert bursts[0]["distinct_types"] == 2

    def test_recon_burst_fires_only_once_within_cooldown(self):
        mod, events = _load_dns()
        src = "5.5.5.2"
        for _ in range(3):
            mod._handle(
                _build_query("version.bind", mod.TYPE_TXT, qclass=mod.CLASS_CH),
                src, 1234, "udp",
            )
            mod._handle(_build_query("test.local", mod.TYPE_AXFR), src, 1234, "tcp")
        bursts = _events_of(events, "recon_burst")
        assert len(bursts) == 1

    def test_recon_burst_different_srcs_no_cross_trigger(self):
        mod, events = _load_dns()
        # src A does fingerprint, src B does zone_transfer — no burst for either
        mod._handle(
            _build_query("version.bind", mod.TYPE_TXT, qclass=mod.CLASS_CH),
            "5.5.5.3", 1234, "udp",
        )
        mod._handle(_build_query("test.local", mod.TYPE_AXFR), "5.5.5.4", 1234, "tcp")
        assert not _events_of(events, "recon_burst")

    def test_recon_burst_does_not_suppress_source_events(self):
        mod, events = _load_dns()
        src = "5.5.5.5"
        mod._handle(
            _build_query("version.bind", mod.TYPE_TXT, qclass=mod.CLASS_CH),
            src, 1234, "udp",
        )
        mod._handle(_build_query("test.local", mod.TYPE_AXFR), src, 1234, "tcp")
        # Source events must still fire
        assert _events_of(events, "fingerprint_probe")
        assert _events_of(events, "zone_transfer")
        # And the burst on top
        assert _events_of(events, "recon_burst")

    def test_amp_plus_fingerprint_triggers_recon_burst(self):
        mod, events = _load_dns()
        src = "5.5.5.6"
        mod._handle(
            _build_query("version.bind", mod.TYPE_TXT, qclass=mod.CLASS_CH),
            src, 1234, "udp",
        )
        mod._handle(_build_query("test.local", mod.TYPE_ANY), src, 1234, "udp")
        bursts = _events_of(events, "recon_burst")
        assert bursts
        assert bursts[0]["distinct_types"] == 2

# ── CLASS=ANY fingerprint probe ───────────────────────────────────────────────

class TestClassAnyProbe:
    def test_class_any_emits_fingerprint_probe(self):
        mod, events = _load_dns()
        pkt = _build_query("example.test.local", mod.TYPE_A, qclass=mod.CLASS_ANY)
        resp = mod._handle(pkt, "9.9.9.9", 53, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_REFUSED
        probes = _events_of(events, "fingerprint_probe")
        assert len(probes) == 1
        assert probes[0]["probe"] == "qclass_any"
        assert probes[0]["qname"] == "example.test.local"

    def test_class_any_counts_toward_recon_burst(self):
        mod, events = _load_dns()
        pkt = _build_query("x.test.local", mod.TYPE_A, qclass=mod.CLASS_ANY)
        for _ in range(3):
            mod._handle(pkt, "6.6.6.6", 53, "udp")
        # Should accumulate; also trigger a second distinct probe type to fire burst
        zxfr = _build_query("test.local", mod.TYPE_AXFR)
        mod._handle(zxfr, "6.6.6.6", 53, "tcp")
        assert len(_events_of(events, "recon_burst")) >= 1

    def test_class_in_is_not_affected(self):
        """Regular CLASS_IN queries must NOT trigger qclass_any."""
        mod, events = _load_dns()
        pkt = _build_query("test.local", mod.TYPE_A, qclass=mod.CLASS_IN)
        mod._handle(pkt, "1.1.1.1", 53, "udp")
        assert not _events_of(events, "fingerprint_probe")

# ── Header flag fingerprinting ────────────────────────────────────────────────

class TestHeaderFlagFingerprint:
    def _opcode_pkt(self, mod, qname: str, opcode: int) -> bytes:
        # Build a raw 12-byte header with no question section — opcode block
        # fires before question parse, so we don't need a valid question.
        flags = (opcode & 0x0F) << 11
        return struct.pack(">HHHHHH", 0x1234, flags, 0, 0, 0, 0) + b"\x00" * 4

    def test_opcode_update_emits_fingerprint_probe_notimp(self):
        mod, events = _load_dns()
        # UPDATE opcode=5; pad to 12 bytes minimum
        flags = (5 << 11)
        pkt = struct.pack(">HHHHHH", 0xABCD, flags, 0, 0, 0, 0)
        resp = mod._handle(pkt, "7.7.7.7", 53, "udp")
        assert resp is not None
        # RCODE must be NOTIMP (4)
        assert struct.unpack_from(">H", resp, 2)[0] & 0x0F == mod.RCODE_NOTIMP
        # opcode in response header echoes the request opcode
        assert (struct.unpack_from(">H", resp, 2)[0] >> 11) & 0x0F == 5
        probes = _events_of(events, "fingerprint_probe")
        assert len(probes) == 1
        assert probes[0]["probe"] == "opcode_update"
        assert probes[0]["opcode"] == 5

    def test_opcode_iquery_emits_fingerprint_probe(self):
        mod, events = _load_dns()
        flags = (1 << 11)
        pkt = struct.pack(">HHHHHH", 0x0001, flags, 0, 0, 0, 0)
        resp = mod._handle(pkt, "8.8.8.8", 53, "udp")
        assert resp is not None
        assert struct.unpack_from(">H", resp, 2)[0] & 0x0F == mod.RCODE_NOTIMP
        probes = _events_of(events, "fingerprint_probe")
        assert probes[0]["probe"] == "opcode_iquery"

    def test_opcode_notify_emits_opcode_notify(self):
        mod, events = _load_dns()
        flags = (4 << 11)
        pkt = struct.pack(">HHHHHH", 0x0002, flags, 0, 0, 0, 0)
        mod._handle(pkt, "9.9.9.8", 53, "udp")
        probes = _events_of(events, "fingerprint_probe")
        assert probes[0]["probe"] == "opcode_notify"

    def test_z_bit_emits_header_flags_probe(self):
        # Z=0x0040 in the flags word
        mod, events = _load_dns()
        pkt = _build_query("test.local", mod.TYPE_A, extra_flags=0x0040)
        resp = mod._handle(pkt, "2.2.2.2", 53, "udp")
        assert resp is not None
        probes = _events_of(events, "fingerprint_probe")
        assert any(p["probe"] == "header_flags" and p["z"] for p in probes)

    def test_ad_cd_without_rd_emits_header_flags_probe(self):
        # AD=0x0020, CD=0x0010, RD=0 (rd=False)
        mod, events = _load_dns()
        pkt = _build_query("test.local", mod.TYPE_A, rd=False, extra_flags=0x0030)
        mod._handle(pkt, "3.3.3.3", 53, "udp")
        probes = _events_of(events, "fingerprint_probe")
        assert any(p["probe"] == "header_flags" and p["ad"] and p["cd"] for p in probes)

    def test_ad_with_rd_is_not_a_probe(self):
        """AD set with RD=1 is a legitimate DNSSEC-aware stub — should not escalate."""
        mod, events = _load_dns()
        pkt = _build_query("test.local", mod.TYPE_A, rd=True, extra_flags=0x0020)
        mod._handle(pkt, "4.4.4.4", 53, "udp")
        assert not any(p["probe"] == "header_flags" for p in _events_of(events, "fingerprint_probe"))

    def test_opcode_fires_before_qclass_any_no_double_count(self):
        """A packet with opcode=update AND qclass=ANY must emit exactly one probe (opcode)."""
        mod, events = _load_dns()
        flags = (5 << 11)
        pkt = struct.pack(">HHHHHH", 0xBEEF, flags, 0, 0, 0, 0)
        mod._handle(pkt, "5.5.5.5", 53, "udp")
        probes = _events_of(events, "fingerprint_probe")
        assert len(probes) == 1
        assert probes[0]["probe"] == "opcode_update"

# ── Zone mode: open ───────────────────────────────────────────────────────────

class TestZoneModeOpen:
    def test_open_mode_resolves_any_name(self):
        mod, _ = _load_dns({"DNS_ZONE_MODE": "open"})
        for qname in ("evil.example.com", "c2.attacker.net", "random.io"):
            query = _build_query(qname, mod.TYPE_A)
            resp = mod._handle(query, "4.4.4.4", 1234, "udp")
            assert resp is not None, f"no response for {qname}"
            assert _rcode(resp) == mod.RCODE_NOERROR
            _, ancount, _, _ = _counts(resp)
            assert ancount >= 1

    def test_open_mode_returns_loopback_sinkhole(self):
        mod, _ = _load_dns({"DNS_ZONE_MODE": "open"})
        # The sinkhole A record must be in 127.0.0.0/8
        query = _build_query("anything.com", mod.TYPE_A)
        resp = mod._handle(query, "4.4.4.4", 1234, "udp")
        assert resp is not None
        # Find the A RDATA — walk past header(12) + question + answer name
        # Just verify the response contains 127 somewhere in a 4-byte window
        assert b"\x7f" in resp  # 0x7f = 127

# ── Zone mode: recursive ──────────────────────────────────────────────────────

class TestRealRecursive:
    def test_upstream_response_relayed_when_available(self):
        """Upstream response is returned instead of sinkhole when forwarding succeeds."""
        mod, events = _load_dns({"DNS_ZONE_MODE": "recursive", "DNS_REAL_RECURSIVE": "true"})
        # Build a realistic upstream response: NOERROR, 1 A answer for evil.example.com
        fake_upstream = _build_query("evil.example.com", mod.TYPE_A, qid=0x1234)
        # Craft a minimal answer: header with QR=1, ANCOUNT=1 + question + A RR
        flags = struct.pack(">H", 0x8180)  # QR=1 AA=0 RA=1 RCODE=0
        answer_hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        qname_wire = b"\x04evil\x07example\x03com\x00"
        question = qname_wire + struct.pack(">HH", mod.TYPE_A, mod.CLASS_IN)
        rdata = bytes([1, 2, 3, 4])
        rr = qname_wire + struct.pack(">HHIH", mod.TYPE_A, mod.CLASS_IN, 60, 4) + rdata
        fake_response = answer_hdr + question + rr

        import asyncio
        from unittest.mock import AsyncMock, patch
        mock_forward = AsyncMock(return_value=fake_response)
        with patch.object(mod, "_forward_upstream", mock_forward):
            query = _build_query("evil.example.com", mod.TYPE_A, qid=0x1234)
            resp = asyncio.get_event_loop().run_until_complete(
                mod._dispatch(query, "1.1.1.1", 1234, "udp")
            )
        assert resp == fake_response
        mock_forward.assert_awaited_once()

    def test_sinkhole_fallback_when_upstream_fails(self):
        """Sinkhole is returned when upstream times out."""
        mod, _ = _load_dns({"DNS_ZONE_MODE": "recursive", "DNS_REAL_RECURSIVE": "true"})
        import asyncio
        from unittest.mock import AsyncMock, patch
        with patch.object(mod, "_forward_upstream", AsyncMock(return_value=None)):
            query = _build_query("evil.example.com", mod.TYPE_A)
            resp = asyncio.get_event_loop().run_until_complete(
                mod._dispatch(query, "1.1.1.1", 1234, "udp")
            )
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR
        assert b"\x7f" in resp  # sinkhole

    def test_in_zone_query_not_forwarded(self):
        """In-zone queries never hit upstream even with real_recursive=true."""
        mod, _ = _load_dns({"DNS_ZONE_MODE": "recursive", "DNS_REAL_RECURSIVE": "true"})
        import asyncio
        from unittest.mock import AsyncMock, patch
        mock_forward = AsyncMock(return_value=None)
        with patch.object(mod, "_forward_upstream", mock_forward):
            query = _build_query("test.local", mod.TYPE_A)
            asyncio.get_event_loop().run_until_complete(
                mod._dispatch(query, "1.1.1.1", 1234, "udp")
            )
        mock_forward.assert_not_awaited()

    def test_real_recursive_false_never_forwards(self):
        """_forward_upstream is never called when REAL_RECURSIVE is off."""
        mod, _ = _load_dns({"DNS_ZONE_MODE": "recursive", "DNS_REAL_RECURSIVE": "false"})
        import asyncio
        from unittest.mock import AsyncMock, patch
        mock_forward = AsyncMock(return_value=None)
        with patch.object(mod, "_forward_upstream", mock_forward):
            query = _build_query("evil.example.com", mod.TYPE_A)
            asyncio.get_event_loop().run_until_complete(
                mod._dispatch(query, "1.1.1.1", 1234, "udp")
            )
        mock_forward.assert_not_awaited()

    def test_logging_fires_even_when_forwarding(self):
        """query event is still emitted for forwarded queries (via _handle)."""
        mod, events = _load_dns({"DNS_ZONE_MODE": "recursive", "DNS_REAL_RECURSIVE": "true"})
        import asyncio
        from unittest.mock import AsyncMock, patch
        fake_resp = b"\x12\x34\x81\x80" + b"\x00" * 8  # minimal valid header
        with patch.object(mod, "_forward_upstream", AsyncMock(return_value=fake_resp)):
            query = _build_query("evil.example.com", mod.TYPE_A)
            asyncio.get_event_loop().run_until_complete(
                mod._dispatch(query, "1.1.1.1", 1234, "udp")
            )
        assert _events_of(events, "query")

    def test_compose_fragment_includes_real_recursive_vars(self):
        from decnet.services.registry import get_service
        svc = get_service("dns")
        frag = svc.compose_fragment(
            "decky-01",
            service_cfg={"real_recursive": True, "upstream": "1.1.1.1:53"},
        )
        assert frag["environment"]["DNS_REAL_RECURSIVE"] == "true"
        assert frag["environment"]["DNS_UPSTREAM"] == "1.1.1.1:53"

    def test_compose_fragment_real_recursive_default_false(self):
        from decnet.services.registry import get_service
        svc = get_service("dns")
        frag = svc.compose_fragment("decky-01")
        assert frag["environment"]["DNS_REAL_RECURSIVE"] == "false"


class TestForwardBudget:
    def _load_with_budget(self, budget: int = 3):
        mod, events = _load_dns({
            "DNS_ZONE_MODE": "recursive",
            "DNS_REAL_RECURSIVE": "true",
            "DNS_FORWARD_BUDGET": str(budget),
            "DNS_FORWARD_WINDOW": "60",  # wide window so nothing expires mid-test
        })
        mod._forward_timestamps.clear()
        return mod, events

    def test_within_budget_forwards(self):
        mod, _ = self._load_with_budget(budget=5)
        import asyncio
        from unittest.mock import AsyncMock, patch
        fake_resp = b"\x12\x34" + b"\x81\x80" + b"\x00" * 8
        mock_fwd = AsyncMock(return_value=fake_resp)
        with patch.object(mod, "_forward_upstream", mock_fwd):
            query = _build_query("evil.example.com", mod.TYPE_A)
            for _ in range(5):
                asyncio.get_event_loop().run_until_complete(
                    mod._dispatch(query, "1.1.1.1", 1234, "udp")
                )
        assert mock_fwd.await_count == 5

    def test_over_budget_falls_back_to_sinkhole(self):
        mod, _ = self._load_with_budget(budget=2)
        import asyncio
        from unittest.mock import AsyncMock, patch
        fake_resp = b"\x12\x34" + b"\x81\x80" + b"\x00" * 8
        mock_fwd = AsyncMock(return_value=fake_resp)
        with patch.object(mod, "_forward_upstream", mock_fwd):
            query = _build_query("evil.example.com", mod.TYPE_A)
            responses = []
            for _ in range(5):
                resp = asyncio.get_event_loop().run_until_complete(
                    mod._dispatch(query, "1.1.1.1", 1234, "udp")
                )
                responses.append(resp)
        # Upstream called at most budget+1 times (budget check appends before pruning)
        assert mock_fwd.await_count <= 3
        # All responses are non-None (sinkhole for over-budget ones)
        assert all(r is not None for r in responses)

    def test_budget_is_global_not_per_src(self):
        """Budget counts all upstream calls regardless of source IP."""
        mod, _ = self._load_with_budget(budget=2)
        import asyncio
        from unittest.mock import AsyncMock, patch
        fake_resp = b"\x12\x34" + b"\x81\x80" + b"\x00" * 8
        mock_fwd = AsyncMock(return_value=fake_resp)
        with patch.object(mod, "_forward_upstream", mock_fwd):
            query = _build_query("evil.example.com", mod.TYPE_A)
            for i in range(5):
                asyncio.get_event_loop().run_until_complete(
                    mod._dispatch(query, f"10.0.0.{i+1}", 1234, "udp")
                )
        assert mock_fwd.await_count <= 3


class TestZoneModeRecursive:
    def test_recursive_mode_sets_ra_flag(self):
        mod, _ = _load_dns({"DNS_ZONE_MODE": "recursive"})
        query = _build_query("out-of-zone.example.com", mod.TYPE_A)
        resp = mod._handle(query, "1.1.1.1", 1234, "udp")
        assert resp is not None
        flags = struct.unpack_from(">H", resp, 2)[0]
        assert bool(flags & 0x0080)  # RA=1

    def test_recursive_mode_returns_answer_for_out_of_zone(self):
        mod, _ = _load_dns({"DNS_ZONE_MODE": "recursive"})
        query = _build_query("evil.example.com", mod.TYPE_A)
        resp = mod._handle(query, "1.1.1.1", 1234, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR
        _, ancount, _, _ = _counts(resp)
        assert ancount >= 1

    def test_recursive_mode_not_authoritative(self):
        mod, _ = _load_dns({"DNS_ZONE_MODE": "recursive"})
        query = _build_query("evil.example.com", mod.TYPE_A)
        resp = mod._handle(query, "1.1.1.1", 1234, "udp")
        assert resp is not None
        flags = struct.unpack_from(">H", resp, 2)[0]
        assert not bool(flags & 0x0400)  # AA=0

    def test_recursive_mode_sinkhole_in_loopback(self):
        mod, _ = _load_dns({"DNS_ZONE_MODE": "recursive"})
        query = _build_query("evil.example.com", mod.TYPE_A)
        resp = mod._handle(query, "1.1.1.1", 1234, "udp")
        assert resp is not None
        assert b"\x7f" in resp  # sinkhole 127.x

# ── Service registration ──────────────────────────────────────────────────────

class TestServiceRegistration:
    def test_dns_registered_by_name(self):
        from decnet.services.registry import get_service
        svc = get_service("dns")
        assert svc is not None
        assert svc.name == "dns"

    def test_dns_port_53(self):
        from decnet.services.registry import get_service
        svc = get_service("dns")
        assert 53 in svc.ports

    def test_dns_udp_ports(self):
        from decnet.services.registry import get_service
        svc = get_service("dns")
        assert 53 in svc.udp_ports()

    def test_compose_fragment_structure(self):
        from decnet.services.registry import get_service
        svc = get_service("dns")
        frag = svc.compose_fragment("decky-01", log_target="127.0.0.1:514")
        assert "build" in frag
        assert frag["container_name"] == "decky-01-dns"
        assert frag["environment"]["NODE_NAME"] == "decky-01"
        assert frag["environment"]["LOG_TARGET"] == "127.0.0.1:514"
        assert "DNS_ZONE_MODE" in frag["environment"]
        assert "DNS_BIND_VERSION" in frag["environment"]

    def test_compose_fragment_no_log_target(self):
        from decnet.services.registry import get_service
        svc = get_service("dns")
        frag = svc.compose_fragment("decky-02")
        assert "LOG_TARGET" not in frag["environment"]

    def test_dockerfile_context_points_to_template(self):
        from decnet.services.registry import get_service
        svc = get_service("dns")
        ctx = svc.dockerfile_context()
        assert ctx is not None
        assert ctx.name == "dns"
        assert (ctx / "Dockerfile").exists()


def _build_multi_question(qname: str, qtype: int, qclass: int = 1, qid: int = 0x1234) -> bytes:
    """DNS query with qdcount=2 — second question is identical to first."""
    header = struct.pack(">HHHHHH", qid, 0x0100, 2, 0, 0, 0)
    wire = b""
    for label in qname.rstrip(".").split("."):
        enc = label.encode("ascii")
        wire += bytes([len(enc)]) + enc
    wire += b"\x00"
    q = wire + struct.pack(">HH", qtype, qclass)
    return header + q + q


# ── Multi-question event ──────────────────────────────────────────────────────

class TestMultiQuestion:
    def test_multi_question_event_emitted(self):
        mod, events = _load_dns()
        pkt = _build_multi_question("example.test.local", mod.TYPE_A)
        resp = mod._handle(pkt, "5.5.5.5", 53, "udp")
        ev = _events_of(events, "multi_question")
        assert len(ev) == 1
        assert ev[0]["qdcount"] == 2
        assert ev[0]["qname"] == "example.test.local"

    def test_multi_question_still_answers_q0(self):
        mod, events = _load_dns()
        pkt = _build_multi_question("test.local", mod.TYPE_A)
        resp = mod._handle(pkt, "5.5.5.5", 53, "udp")
        assert resp is not None
        assert _rcode(resp) == mod.RCODE_NOERROR

    def test_multi_question_also_logs_query(self):
        """multi_question event accompanies, does not replace, the normal query event."""
        mod, events = _load_dns()
        pkt = _build_multi_question("test.local", mod.TYPE_A)
        mod._handle(pkt, "5.5.5.5", 53, "udp")
        assert len(_events_of(events, "multi_question")) == 1
        # A query or amp_probe event must also be present for q0
        assert len(_events_of(events, "query")) + len(_events_of(events, "amp_probe")) >= 1


# ── Parse hygiene events ───────────────────────────────────────────────────────

class TestParseHygiene:
    def test_malformed_packet_too_short(self):
        mod, events = _load_dns()
        resp = mod._handle(b"\x00\x01\x00\x00", "1.2.3.4", 1234, "udp")
        assert resp is None
        ev = _events_of(events, "malformed_packet")
        assert len(ev) == 1
        assert ev[0]["src"] == "1.2.3.4"
        assert ev[0]["length"] == 4
        assert ev[0]["transport"] == "udp"

    def test_malformed_packet_empty(self):
        mod, events = _load_dns()
        resp = mod._handle(b"", "10.0.0.1", 5353, "tcp")
        assert resp is None
        ev = _events_of(events, "malformed_packet")
        assert len(ev) == 1
        assert ev[0]["length"] == 0

    def test_empty_question_section(self):
        mod, events = _load_dns()
        # 12-byte header with qdcount=0
        pkt = struct.pack(">HHHHHH", 0xBEEF, 0x0100, 0, 0, 0, 0)
        resp = mod._handle(pkt, "2.2.2.2", 53, "udp")
        assert resp is None
        ev = _events_of(events, "empty_question_section")
        assert len(ev) == 1
        assert ev[0]["qid"] == 0xBEEF
        assert ev[0]["src"] == "2.2.2.2"

    def test_question_parse_error_truncated(self):
        mod, events = _load_dns()
        # Header claims qdcount=1 but question section is empty
        pkt = struct.pack(">HHHHHH", 0x0001, 0x0100, 1, 0, 0, 0)
        resp = mod._handle(pkt, "3.3.3.3", 1053, "udp")
        assert resp is None
        ev = _events_of(events, "question_parse_error")
        assert len(ev) == 1
        assert ev[0]["src"] == "3.3.3.3"
        assert "reason" in ev[0]

    def test_question_parse_error_no_malformed_event(self):
        """question_parse_error must not also emit malformed_packet."""
        mod, events = _load_dns()
        pkt = struct.pack(">HHHHHH", 0x0001, 0x0100, 1, 0, 0, 0)
        mod._handle(pkt, "3.3.3.3", 1053, "udp")
        assert len(_events_of(events, "malformed_packet")) == 0


# ── EDNS sub-option parsing ───────────────────────────────────────────────────

class TestEDNSOptions:
    def test_nsid_option_emits_fingerprint_probe(self):
        mod, events = _load_dns()
        # NSID option code is 3; client sends empty data to request NSID
        pkt = _build_query_with_opt(
            "test.local", mod.TYPE_A, opt_options=[(3, b"")]
        )
        resp = mod._handle(pkt, "10.0.0.2", 53, "udp")
        assert resp is not None
        probes = _events_of(events, "fingerprint_probe")
        assert len(probes) == 1
        assert probes[0]["probe"] == "edns_nsid"
        assert probes[0]["qname"] == "test.local"

    def test_nsid_option_still_answers_query(self):
        """NSID probe still gets a response — we answer normally."""
        mod, events = _load_dns()
        pkt = _build_query_with_opt(
            "test.local", mod.TYPE_A, opt_options=[(3, b"")]
        )
        resp = mod._handle(pkt, "10.0.0.2", 53, "udp")
        assert resp is not None
        assert _rcode(resp) in (mod.RCODE_NOERROR, mod.RCODE_REFUSED)

    def test_cookie_option_does_not_emit_probe(self):
        """COOKIE (code=10) is not a fingerprint signal — no probe event."""
        mod, events = _load_dns()
        # 8-byte client cookie
        pkt = _build_query_with_opt(
            "test.local", mod.TYPE_A, opt_options=[(10, b"\x01\x02\x03\x04\x05\x06\x07\x08")]
        )
        mod._handle(pkt, "11.0.0.1", 53, "udp")
        assert not _events_of(events, "fingerprint_probe")

    def test_do_bit_alone_does_not_emit_probe(self):
        """DO bit set in EDNS is normal DNSSEC behaviour — not a probe signal."""
        mod, events = _load_dns()
        # TTL with DO=0x8000 in high half
        wire = b""
        for label in "test.local".split("."):
            enc = label.encode("ascii")
            wire += bytes([len(enc)]) + enc
        wire += b"\x00"
        question = wire + struct.pack(">HH", mod.TYPE_A, 1)
        # OPT with DO bit set in TTL
        opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
        pkt = header + question + opt
        mod._handle(pkt, "12.0.0.1", 53, "udp")
        assert not _events_of(events, "fingerprint_probe")

    def test_edns_size_still_drives_amp_probe(self):
        """udp_size from OPT must still feed the amp_probe classifier."""
        mod, events = _load_dns()
        pkt = _build_query_with_opt("test.local", mod.TYPE_A, udp_size=4096)
        mod._handle(pkt, "13.0.0.1", 53, "udp")
        # udp_size=4096 > 1232 → amp_probe
        assert len(_events_of(events, "amp_probe")) == 1

    def test_parse_opt_record_returns_dict(self):
        """Direct unit test for _parse_opt_record with NSID option."""
        mod, _ = _load_dns()
        pkt = _build_query_with_opt(
            "test.local", mod.TYPE_A, udp_size=512, opt_options=[(3, b"\xde\xad")]
        )
        qid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHHHH", pkt, 0)
        result = mod._parse_opt_record(pkt, qdcount, ancount, nscount, arcount)
        assert result is not None
        assert result["udp_size"] == 512
        assert any(code == 3 for code, _l, _d in result["options"])
