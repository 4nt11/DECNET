# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for TCP retransmit detection in the SnifferEngine flow aggregator.

A retransmit is defined as a *forward-direction* (attacker → decky) TCP
segment carrying payload whose sequence number has already been seen on
this flow. Empty SYN/ACKs that share seq legitimately are excluded.
"""

from __future__ import annotations

from scapy.layers.inet import IP, TCP

from decnet.sniffer.fingerprint import SnifferEngine


_DECKY_IP = "192.168.1.10"
_DECKY = "decky-01"
_ATTACKER_IP = "10.0.0.7"


def _mk_engine() -> tuple[SnifferEngine, list[str]]:
    captured: list[str] = []
    engine = SnifferEngine(
        ip_to_decky={_DECKY_IP: _DECKY},
        write_fn=captured.append,
        dedup_ttl=0,  # disable dedup for easier assertion
    )
    return engine, captured


def _data_pkt(seq: int, payload: bytes = b"data", sport: int = 55555):
    return IP(src=_ATTACKER_IP, dst=_DECKY_IP, ttl=64) / TCP(
        sport=sport, dport=22, flags="A", seq=seq, window=29200,
    ) / payload


def _rst(sport: int = 55555):
    return IP(src=_DECKY_IP, dst=_ATTACKER_IP, ttl=64) / TCP(
        sport=22, dport=sport, flags="R",
    )


def _extract_retransmits(lines: list[str]) -> int:
    """Pull `retransmits=` from the last tcp_flow_timing line."""
    import re
    for line in reversed(lines):
        if "tcp_flow_timing" not in line:
            continue
        m = re.search(r'retransmits="(\d+)"', line)
        if m:
            return int(m.group(1))
    return -1


class TestRetransmitDetection:
    def test_no_retransmits_when_seqs_unique(self):
        engine, captured = _mk_engine()
        engine.on_packet(_data_pkt(seq=1000))
        engine.on_packet(_data_pkt(seq=1004))
        engine.on_packet(_data_pkt(seq=1008))
        engine.on_packet(_rst())
        assert _extract_retransmits(captured) == 0

    def test_single_retransmit(self):
        engine, captured = _mk_engine()
        engine.on_packet(_data_pkt(seq=2000))
        engine.on_packet(_data_pkt(seq=2004))
        engine.on_packet(_data_pkt(seq=2000))  # retransmitted
        engine.on_packet(_rst())
        assert _extract_retransmits(captured) == 1

    def test_multiple_retransmits(self):
        engine, captured = _mk_engine()
        engine.on_packet(_data_pkt(seq=3000))
        engine.on_packet(_data_pkt(seq=3000))
        engine.on_packet(_data_pkt(seq=3000))
        engine.on_packet(_data_pkt(seq=3004))
        engine.on_packet(_rst())
        # Two retransmits (original + 2 dupes of seq=3000)
        assert _extract_retransmits(captured) == 2

    def test_reverse_direction_not_counted(self):
        """Packets from decky → attacker sharing seq should NOT count."""
        engine, captured = _mk_engine()
        # Forward data
        engine.on_packet(_data_pkt(seq=4000))
        engine.on_packet(_data_pkt(seq=4004))
        engine.on_packet(_data_pkt(seq=4008))
        # Reverse response (decky → attacker) with same seq as a forward
        # packet — different flow direction, must not count as retransmit.
        reverse = IP(src=_DECKY_IP, dst=_ATTACKER_IP, ttl=64) / TCP(
            sport=22, dport=55555, flags="A", seq=4000, window=29200,
        ) / b"resp"
        engine.on_packet(reverse)
        engine.on_packet(_rst())
        assert _extract_retransmits(captured) == 0

    def test_empty_segments_not_counted(self):
        """Pure ACKs (no payload) are not retransmits even if seqs repeat."""
        engine, captured = _mk_engine()
        # Three pure-ACKs with identical seq
        for _ in range(3):
            pkt = IP(src=_ATTACKER_IP, dst=_DECKY_IP, ttl=64) / TCP(
                sport=55555, dport=22, flags="A", seq=5000, window=29200,
            )
            engine.on_packet(pkt)
        engine.on_packet(_rst())
        assert _extract_retransmits(captured) == 0
