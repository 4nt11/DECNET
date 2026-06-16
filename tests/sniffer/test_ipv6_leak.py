# SPDX-License-Identifier: AGPL-3.0-or-later
"""Passive IPv6 link-local leak detection — sniffer unit tests.

Tests SnifferEngine._on_ipv6_packet and _ipv6_iid_classify via direct
packet injection (no sniff thread — per project constraint on scapy sniff
threads in pytest teardown).
"""
from __future__ import annotations

import pytest

from scapy.layers.inet6 import ICMPv6ND_NS, IPv6

from decnet.sniffer.fingerprint import SnifferEngine, _ipv6_iid_classify

_DECKY_IP6 = "fe80::1"   # decky's own link-local (destination)
_DECKY_IP4 = "10.0.0.5"  # corresponding v4 for ip_to_decky mapping
_DECKY = "decky-a"

# EUI-64 derived from MAC aa:bb:cc:dd:ee:ff →
#   bytes: aa^0x02, bb, cc, ff, fe, dd, ee, ff
# → IID: a8:bb:cc:ff:fe:dd:ee:ff → fe80::aabb:ccff:fedd:eeff
_EUI64_ADDR = "fe80::aabb:ccff:fedd:eeff"
_EUI64_OUI  = "a8:bb:cc"   # U/L bit flipped (aa XOR 0x02 = a8)

# Stable-privacy / random IID — no fffe bytes at positions 3-4
_STABLE_ADDR = "fe80::1234:5678:9abc:def0"


def _engine(extra_map: dict[str, str] | None = None) -> tuple[SnifferEngine, list[str]]:
    captured: list[str] = []
    ip_map = {_DECKY_IP4: _DECKY}
    if extra_map:
        ip_map.update(extra_map)
    engine = SnifferEngine(
        ip_to_decky=ip_map,
        write_fn=captured.append,
        dedup_ttl=300.0,
    )
    return engine, captured


# ── _ipv6_iid_classify ───────────────────────────────────────────────────────


def test_iid_classify_eui64_returns_oui() -> None:
    kind, oui = _ipv6_iid_classify(_EUI64_ADDR)
    assert kind == "eui64"
    assert oui == _EUI64_OUI


def test_iid_classify_stable_privacy() -> None:
    kind, oui = _ipv6_iid_classify(_STABLE_ADDR)
    assert kind == "stable_privacy"
    assert oui == ""


def test_iid_classify_bad_addr_returns_unknown() -> None:
    kind, oui = _ipv6_iid_classify("not-an-address")
    assert kind == "unknown"
    assert oui == ""


# ── _on_ipv6_packet ─────────────────────────────────────────────────────────


def _make_ndp_ns(src: str, dst: str) -> object:
    """Craft a Neighbor Solicitation from attacker link-local to decky."""
    return IPv6(src=src, dst=dst) / ICMPv6ND_NS(tgt=dst)


def test_eui64_packet_emits_ipv6_leak_event() -> None:
    engine, captured = _engine(extra_map={"fe80::1": _DECKY})
    pkt = _make_ndp_ns(_EUI64_ADDR, _DECKY_IP6)
    engine._on_ipv6_packet(pkt)
    assert len(captured) == 1
    line = captured[0]
    assert "ipv6_link_local_leak" in line
    assert _EUI64_ADDR in line
    assert "eui64" in line
    assert _EUI64_OUI in line


def test_stable_privacy_packet_emits_event() -> None:
    engine, captured = _engine(extra_map={"fe80::1": _DECKY})
    pkt = _make_ndp_ns(_STABLE_ADDR, _DECKY_IP6)
    engine._on_ipv6_packet(pkt)
    assert len(captured) == 1
    assert "stable_privacy" in captured[0]


def test_non_link_local_src_is_ignored() -> None:
    engine, captured = _engine(extra_map={"fe80::1": _DECKY})
    # GUA source — not a link-local leak
    pkt = IPv6(src="2001:db8::1", dst=_DECKY_IP6) / ICMPv6ND_NS(tgt=_DECKY_IP6)
    engine._on_ipv6_packet(pkt)
    assert captured == []


def test_packet_to_unknown_decky_is_ignored() -> None:
    engine, captured = _engine()  # ip_to_decky has no v6 entries
    pkt = _make_ndp_ns(_EUI64_ADDR, "fe80::dead")
    engine._on_ipv6_packet(pkt)
    assert captured == []


def test_on_packet_dispatches_ipv6_branch() -> None:
    """on_packet() must route IPv6 packets to _on_ipv6_packet."""
    engine, captured = _engine(extra_map={"fe80::1": _DECKY})
    pkt = _make_ndp_ns(_EUI64_ADDR, _DECKY_IP6)
    engine.on_packet(pkt)
    assert any("ipv6_link_local_leak" in line for line in captured)


def test_dedup_suppresses_repeat_emit() -> None:
    engine, captured = _engine(extra_map={"fe80::1": _DECKY})
    pkt = _make_ndp_ns(_EUI64_ADDR, _DECKY_IP6)
    engine._on_ipv6_packet(pkt)
    engine._on_ipv6_packet(pkt)
    assert len(captured) == 1  # second identical packet deduped


def test_publish_fn_fires_on_leak() -> None:
    published: list[tuple[str, str, dict]] = []
    engine = SnifferEngine(
        ip_to_decky={"fe80::1": _DECKY},
        write_fn=lambda _: None,
        publish_fn=lambda node, event, payload: published.append((node, event, payload)),
    )
    pkt = _make_ndp_ns(_EUI64_ADDR, _DECKY_IP6)
    engine._on_ipv6_packet(pkt)
    assert len(published) == 1
    node, event, payload = published[0]
    assert event == "ipv6_link_local_leak"
    assert payload["iid_kind"] == "eui64"
    assert payload["mac_oui"] == _EUI64_OUI
