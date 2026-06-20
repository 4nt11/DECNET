# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Tests for the cloak mangler/responder PURE logic — option layout, IP-ID policy,
probe classification, reply fields. No scapy, root, or live NFQUEUE involved
(the runtime loops are exercised only on real deckies, not in CI).
"""
from __future__ import annotations

import pytest

from decnet.cloak import (
    ProbeKind,
    build_reply_fields,
    build_synack_options,
    classify_probe,
    next_ipid,
)
from decnet.cloak.mangler import _is_synack, _rst_needs_ack
from decnet.os_fingerprint import OS_MANGLE, MangleProfile, get_os_mangle

WIN = OS_MANGLE["windows"]
SRV = OS_MANGLE["windows_server"]


# ── profile wiring ──────────────────────────────────────────────────────────

def test_get_os_mangle_known():
    assert isinstance(get_os_mangle("windows"), MangleProfile)
    assert get_os_mangle("windows_server").ipid == "random"


def test_get_os_mangle_none_for_linux():
    assert get_os_mangle("linux") is None
    assert get_os_mangle("nonexistent") is None


def test_windows_workstation_ipid_is_incr():
    # Win10 workstation = incremental IP-ID (nmap TI=I); server = randomized (RD).
    assert WIN.ipid == "incr"
    assert SRV.ipid == "random"


# ── SYN-ACK option building ─────────────────────────────────────────────────

def test_options_layout_with_timestamp_preserved():
    orig = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (111, 222)),
            ("NOP", None), ("WScale", 7)]
    out = build_synack_options(orig, WIN)
    names = [n for n, _ in out]
    assert names == ["MSS", "NOP", "WScale", "SAckOK", "Timestamp"]
    # the kernel's live timestamp value must survive (SEQ.TS rate test)
    assert ("Timestamp", (111, 222)) in out
    # our chosen mss/wscale override whatever the kernel emitted
    assert ("MSS", WIN.mss) in out
    assert ("WScale", WIN.wscale) in out


def test_options_drop_timestamp_when_kernel_had_none():
    """If timestamps are off (no kernel TS option), emit none — never a fake one."""
    orig = [("MSS", 1460), ("SAckOK", b""), ("NOP", None), ("WScale", 7)]
    out = build_synack_options(orig, WIN)
    assert all(n != "Timestamp" for n, _ in out)


def test_options_length_is_4byte_aligned():
    """Sanity: the windows option layout encodes to a multiple of 4 bytes."""
    from scapy.all import TCP  # type: ignore  # noqa
    pytest.importorskip("scapy")
    orig = [("MSS", 1460), ("Timestamp", (1, 2))]
    out = build_synack_options(orig, WIN)
    raw = bytes(TCP(options=out))[20:]  # options after the 20-byte base header
    assert len(raw) % 4 == 0


# ── IP-ID policy ────────────────────────────────────────────────────────────

def test_next_ipid_incr_wraps():
    assert next_ipid(5, "incr") == 6
    assert next_ipid(0xFFFF, "incr") == 0


def test_next_ipid_random_in_range_nonzero():
    for _ in range(50):
        v = next_ipid(0, "random")
        assert 1 <= v <= 0xFFFF


def test_next_ipid_keep_sentinel():
    assert next_ipid(123, "keep") == -1


# ── SYN-ACK detection ───────────────────────────────────────────────────────

@pytest.mark.parametrize("flags,expected", [
    (0x12, True),    # SYN+ACK
    (0x52, True),    # SYN+ACK+ECE (ECN SYN-ACK)
    (0x02, False),   # bare SYN
    (0x10, False),   # bare ACK
])
def test_is_synack(flags, expected):
    assert _is_synack(flags) is expected


@pytest.mark.parametrize("flags,expected", [
    (0x04, True),    # bare RST (T4/T6 ACK-probe response) → fill ack (A=O)
    (0x14, False),   # RST+ACK (T5/T7) → already A=S+, leave
    (0x12, False),   # SYN+ACK
])
def test_rst_needs_ack(flags, expected):
    assert _rst_needs_ack(flags) is expected


# ── probe classification ────────────────────────────────────────────────────

OPEN = frozenset({22, 80, 443})


def test_classify_t2_null_flags_open_port():
    assert classify_probe(0x00, 80, OPEN) is ProbeKind.T2


def test_classify_t3_synfinpshurg_open_port():
    assert classify_probe(0x2B, 80, OPEN) is ProbeKind.T3


def test_classify_ignores_closed_port():
    assert classify_probe(0x00, 9999, OPEN) is None


def test_classify_ignores_normal_traffic():
    assert classify_probe(0x02, 80, OPEN) is None   # SYN — real stack handles
    assert classify_probe(0x10, 80, OPEN) is None   # ACK


# ── reply field shaping ─────────────────────────────────────────────────────

def test_reply_fields_t2_ack_equals_probe_seq():
    # T2: A=S (ack == probe seq)
    f = build_reply_fields(0xDEAD, ProbeKind.T2)
    assert f == {"seq": 0, "ack": 0xDEAD, "flags": "RA", "window": 0, "df": True}


def test_reply_fields_t3_ack_is_other():
    # T3: A=O (other — not zero, not the probe seq)
    f = build_reply_fields(0xDEAD, ProbeKind.T3)
    assert f["ack"] not in (0, 0xDEAD)
    assert f["seq"] == 0 and f["flags"] == "RA"
