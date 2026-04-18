"""
Integration tests for TCP-level passive fingerprinting in the SnifferEngine.

Covers end-to-end flow from a scapy packet through `on_packet()` to:
    - tcp_syn_fingerprint event emission (OS guess, options, hop distance)
    - tcp_flow_timing event emission (packet count, duration, retransmits)
    - dedup behavior (one event per unique fingerprint per window)
    - flow flush on FIN/RST
"""

from __future__ import annotations

from scapy.layers.inet import IP, TCP

from decnet.sniffer.fingerprint import SnifferEngine


# ─── Helpers ────────────────────────────────────────────────────────────────

_DECKY_IP = "192.168.1.10"
_DECKY = "decky-01"
_ATTACKER_IP = "10.0.0.7"


def _make_engine() -> tuple[SnifferEngine, list[str]]:
    """Return (engine, captured_syslog_lines)."""
    captured: list[str] = []
    engine = SnifferEngine(
        ip_to_decky={_DECKY_IP: _DECKY},
        write_fn=captured.append,
        dedup_ttl=300.0,
    )
    return engine, captured


def _linux_syn(src_port: int = 45000, dst_port: int = 22, seq: int = 1000):
    """Build a synthetic SYN that should fingerprint as Linux."""
    return IP(src=_ATTACKER_IP, dst=_DECKY_IP, ttl=64) / TCP(
        sport=src_port,
        dport=dst_port,
        flags="S",
        seq=seq,
        window=29200,
        options=[
            ("MSS", 1460),
            ("SAckOK", b""),
            ("Timestamp", (123, 0)),
            ("NOP", None),
            ("WScale", 7),
        ],
    )


def _windows_syn(src_port: int = 45001):
    """Build a synthetic SYN that should fingerprint as Windows."""
    return IP(src=_ATTACKER_IP, dst=_DECKY_IP, ttl=128) / TCP(
        sport=src_port,
        dport=3389,
        flags="S",
        window=64240,
        options=[
            ("MSS", 1460),
            ("NOP", None),
            ("WScale", 8),
            ("NOP", None),
            ("NOP", None),
            ("SAckOK", b""),
        ],
    )


def _fields_from_line(line: str) -> dict[str, str]:
    """Parse the SD-params section of an RFC 5424 syslog line into a dict."""
    import re
    m = re.search(r"\[relay@55555 (.*?)\]", line)
    if not m:
        return {}
    body = m.group(1)
    out: dict[str, str] = {}
    for k, v in re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', body):
        out[k] = v
    return out


def _msgid(line: str) -> str:
    """Extract MSGID from RFC 5424 line."""
    parts = line.split(" ", 6)
    return parts[5] if len(parts) > 5 else ""


# ─── tcp_syn_fingerprint emission ──────────────────────────────────────────

class TestSynFingerprintEmission:
    def test_linux_syn_emits_fingerprint(self):
        engine, captured = _make_engine()
        engine.on_packet(_linux_syn())
        fp_lines = [ln for ln in captured if _msgid(ln) == "tcp_syn_fingerprint"]
        assert len(fp_lines) == 1
        f = _fields_from_line(fp_lines[0])
        assert f["src_ip"] == _ATTACKER_IP
        assert f["dst_ip"] == _DECKY_IP
        assert f["os_guess"] == "linux"
        assert f["ttl"] == "64"
        assert f["initial_ttl"] == "64"
        assert f["hop_distance"] == "0"
        assert f["window"] == "29200"
        assert f["wscale"] == "7"
        assert f["mss"] == "1460"
        assert f["has_sack"] == "true"
        assert f["has_timestamps"] == "true"

    def test_windows_syn_emits_windows_guess(self):
        engine, captured = _make_engine()
        engine.on_packet(_windows_syn())
        fp_lines = [ln for ln in captured if _msgid(ln) == "tcp_syn_fingerprint"]
        assert len(fp_lines) == 1
        f = _fields_from_line(fp_lines[0])
        assert f["os_guess"] == "windows"
        assert f["ttl"] == "128"
        assert f["initial_ttl"] == "128"

    def test_hop_distance_inferred_from_ttl(self):
        engine, captured = _make_engine()
        pkt = IP(src=_ATTACKER_IP, dst=_DECKY_IP, ttl=58) / TCP(
            sport=40000, dport=22, flags="S", window=29200,
            options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (0, 0)),
                     ("NOP", None), ("WScale", 7)],
        )
        engine.on_packet(pkt)
        fp_lines = [ln for ln in captured if _msgid(ln) == "tcp_syn_fingerprint"]
        f = _fields_from_line(fp_lines[0])
        assert f["initial_ttl"] == "64"
        assert f["hop_distance"] == "6"

    def test_dedup_suppresses_repeated_fingerprints(self):
        engine, captured = _make_engine()
        engine.on_packet(_linux_syn(src_port=40001))
        engine.on_packet(_linux_syn(src_port=40002))
        engine.on_packet(_linux_syn(src_port=40003))
        fp_lines = [ln for ln in captured if _msgid(ln) == "tcp_syn_fingerprint"]
        assert len(fp_lines) == 1  # same OS + options_sig deduped

    def test_different_os_not_deduped(self):
        engine, captured = _make_engine()
        engine.on_packet(_linux_syn(src_port=40001))
        engine.on_packet(_windows_syn(src_port=40002))
        fp_lines = [ln for ln in captured if _msgid(ln) == "tcp_syn_fingerprint"]
        assert len(fp_lines) == 2

    def test_decky_source_does_not_emit(self):
        """Packets originating from a decky (outbound reply) should NOT
        be classified as an attacker fingerprint."""
        engine, captured = _make_engine()
        pkt = IP(src=_DECKY_IP, dst=_ATTACKER_IP, ttl=64) / TCP(
            sport=22, dport=40000, flags="S", window=29200,
            options=[("MSS", 1460)],
        )
        engine.on_packet(pkt)
        fp_lines = [ln for ln in captured if _msgid(ln) == "tcp_syn_fingerprint"]
        assert fp_lines == []


# ─── tcp_flow_timing emission ───────────────────────────────────────────────

class TestFlowTiming:
    def test_flow_flushed_on_fin_if_non_trivial(self):
        """A session with ≥4 packets triggers a tcp_flow_timing event on FIN."""
        engine, captured = _make_engine()
        # SYN + 3 data ACKs + FIN = 5 packets → passes the trivial-flow filter
        pkts = [_linux_syn(src_port=50000, seq=100)]
        for i, seq in enumerate((101, 200, 300)):
            pkts.append(
                IP(src=_ATTACKER_IP, dst=_DECKY_IP, ttl=64) / TCP(
                    sport=50000, dport=22, flags="A", seq=seq, window=29200,
                ) / b"hello-data-here"
            )
        pkts.append(
            IP(src=_ATTACKER_IP, dst=_DECKY_IP, ttl=64) / TCP(
                sport=50000, dport=22, flags="FA", seq=400, window=29200,
            )
        )
        for p in pkts:
            engine.on_packet(p)

        flow_lines = [ln for ln in captured if _msgid(ln) == "tcp_flow_timing"]
        assert len(flow_lines) == 1
        f = _fields_from_line(flow_lines[0])
        assert f["src_ip"] == _ATTACKER_IP
        assert f["dst_ip"] == _DECKY_IP
        assert int(f["packets"]) == 5
        assert int(f["retransmits"]) == 0

    def test_trivial_flow_dropped(self):
        """A 2-packet scan probe (SYN + RST) must NOT emit a timing event."""
        engine, captured = _make_engine()
        engine.on_packet(_linux_syn(src_port=50001, seq=200))
        engine.on_packet(
            IP(src=_DECKY_IP, dst=_ATTACKER_IP, ttl=64) / TCP(
                sport=22, dport=50001, flags="R", window=0,
            )
        )
        flow_lines = [ln for ln in captured if _msgid(ln) == "tcp_flow_timing"]
        assert flow_lines == []  # trivial: packets<4, no retransmits, dur<1s

    def test_retransmit_forces_emission_on_short_flow(self):
        """Even a 3-packet flow must emit if it contains a retransmit."""
        engine, captured = _make_engine()
        engine.on_packet(_linux_syn(src_port=50002, seq=300))
        # Repeat a forward data seq → retransmit
        for _ in range(2):
            engine.on_packet(
                IP(src=_ATTACKER_IP, dst=_DECKY_IP, ttl=64) / TCP(
                    sport=50002, dport=22, flags="A", seq=301, window=29200,
                ) / b"payload"
            )
        engine.on_packet(
            IP(src=_DECKY_IP, dst=_ATTACKER_IP, ttl=64) / TCP(
                sport=22, dport=50002, flags="R", window=0,
            )
        )
        flow_lines = [ln for ln in captured if _msgid(ln) == "tcp_flow_timing"]
        assert len(flow_lines) == 1
        f = _fields_from_line(flow_lines[0])
        assert int(f["retransmits"]) == 1

    def test_flush_all_flows_helper_drops_trivial(self):
        """flush_all_flows still filters trivial flows."""
        engine, captured = _make_engine()
        engine.on_packet(_linux_syn(src_port=50003, seq=400))
        engine.flush_all_flows()
        flow_lines = [ln for ln in captured if _msgid(ln) == "tcp_flow_timing"]
        assert flow_lines == []  # single packet = trivial
