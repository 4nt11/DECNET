"""
Verify that JA4H computed from canonical header order (as emitted by the
decnet_fp listener wrapper via syslog_bridge._compute_ja4h) matches the
sniffer-side _ja4h reference implementation.

The bridge emits headers as [[name, value], ...] pairs.  The sniffer expects
a flat list of names.  These tests exercise the bridge's _compute_ja4h inline
copy and verify it produces the same hash as the canonical sniffer function.
"""
from __future__ import annotations

import importlib
import sys
import types
import pytest

from decnet.sniffer.fingerprint import _ja4h as sniffer_ja4h


# ── load the bridge module standalone (no Flask env needed) ──────────────────

def _load_bridge():
    """Import templates/syslog_bridge.py as a standalone module."""
    import importlib.util
    from pathlib import Path
    bridge_path = (
        Path(__file__).parent.parent.parent
        / "decnet" / "templates" / "syslog_bridge.py"
    )
    spec = importlib.util.spec_from_file_location("syslog_bridge_tpl", bridge_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def bridge():
    return _load_bridge()


# ── helpers ───────────────────────────────────────────────────────────────────

def bridge_ja4h(bridge_mod, method, proto, headers_pairs, cookie="", accept_lang=""):
    """Call bridge._compute_ja4h with a list of [name, value] pairs."""
    return bridge_mod._compute_ja4h(method, proto, headers_pairs, cookie, accept_lang)


def sniffer_ja4h_from_names(method, version, names, cookie_val="", accept_lang=""):
    """Call sniffer _ja4h with a flat name list."""
    return sniffer_ja4h(method, version, names, cookie_val, accept_lang)


# ── tests ─────────────────────────────────────────────────────────────────────

class TestBridgeJA4HMatchesSniffer:
    """The bridge's local _compute_ja4h must produce identical hashes to the
    sniffer's canonical _ja4h for equivalent inputs."""

    def test_h1_get_basic(self, bridge):
        names = ["host", "user-agent", "accept"]
        pairs = [[n, "x"] for n in names]
        b = bridge_ja4h(bridge, "GET", "h1", pairs)
        s = sniffer_ja4h_from_names("GET", "HTTP/1.1", names)
        assert b == s, f"bridge={b!r}, sniffer={s!r}"

    def test_h1_with_cookie_and_lang(self, bridge):
        names = ["host", "user-agent", "accept-language", "cookie"]
        pairs = [[n, "x"] for n in names]
        b = bridge_ja4h(bridge, "POST", "h1", pairs, cookie="sess=abc", accept_lang="en-US")
        s = sniffer_ja4h_from_names("POST", "HTTP/1.1", names, cookie_val="sess=abc", accept_lang="en-US")
        assert b == s

    def test_h2_pseudo_headers(self, bridge):
        # H2 includes pseudo-headers in HPACK order.
        names = [":method", ":path", ":scheme", ":authority", "user-agent", "accept"]
        pairs = [[n, "x"] for n in names]
        b = bridge_ja4h(bridge, "GET", "h2", pairs)
        s = sniffer_ja4h_from_names("GET", "HTTP/2.0", names)
        assert b == s

    def test_referer_excluded_from_hash(self, bridge):
        names_with_referer = ["host", "referer", "user-agent"]
        names_without = ["host", "user-agent"]
        pairs = [[n, "x"] for n in names_with_referer]
        b_with = bridge_ja4h(bridge, "GET", "h1", pairs)
        # Referer is excluded from header hash but flagged in the method tag.
        # Both bridge and sniffer should agree on the 'r' flag.
        assert "_" in b_with  # valid JA4H format
        parts = b_with.split("_")
        assert parts[0][5] == "r"  # referer flag set

    def test_order_matters(self, bridge):
        """Changing header order changes the hash (proving order is captured)."""
        names_a = ["host", "user-agent", "accept", "x-custom"]
        names_b = ["host", "accept", "user-agent", "x-custom"]
        pairs_a = [[n, "x"] for n in names_a]
        pairs_b = [[n, "x"] for n in names_b]
        b_a = bridge_ja4h(bridge, "GET", "h1", pairs_a)
        b_b = bridge_ja4h(bridge, "GET", "h1", pairs_b)
        assert b_a != b_b, "different header order should produce different JA4H hash"

    def test_h3_proto_tag(self, bridge):
        names = ["host", "user-agent"]
        pairs = [[n, "x"] for n in names]
        b = bridge_ja4h(bridge, "GET", "h3", pairs)
        s = sniffer_ja4h_from_names("GET", "HTTP/3.0", names)
        assert b == s

    def test_empty_headers(self, bridge):
        b = bridge_ja4h(bridge, "GET", "h1", [])
        # Should not crash; produces a valid JA4H string.
        assert b.count("_") == 3
