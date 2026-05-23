# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the HTML/SVG fingerprint canary generators.

Skipped when the Node toolchain (or vendored javascript-obfuscator) is
not installed, mirroring :mod:`tests.canary.test_obfuscator`.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from decnet.canary import CanaryContext, get_generator


def _toolchain_ready() -> bool:
    if shutil.which("node") is None:
        return False
    canary_dir = Path(__file__).resolve().parents[2] / "decnet" / "canary"
    return (canary_dir / "node_modules" / "javascript-obfuscator").is_dir()


pytestmark = pytest.mark.skipif(
    not _toolchain_ready(),
    reason="node + javascript-obfuscator not installed under decnet/canary",
)


def _ctx(callback_token: str = "fp-tok-123") -> CanaryContext:
    return CanaryContext(
        callback_token=callback_token,
        http_base="https://canary.example.test",
        dns_zone="canary.example.test",
        persona="linux",
    )


def test_fingerprint_html_renders_full_page() -> None:
    art = get_generator("fingerprint_html").generate(_ctx())
    body = art.content.decode("utf-8")
    assert body.startswith("<!DOCTYPE html>")
    assert "<script>" in body and "</script>" in body
    assert "Internal Asset Directory" in body
    assert "<table>" in body
    # Beacon URL must NOT appear in plaintext — it's inside the
    # obfuscated string array. (Sanity: this is the whole point of
    # obfuscating the payload.)
    assert "/c/fp-tok-123" not in body
    # Visible content shouldn't leak the slug either.
    assert "fp-tok-123" not in body
    assert art.mode == 0o644
    assert art.generator == "fingerprint_html"


def test_fingerprint_html_is_deterministic_per_token() -> None:
    a = get_generator("fingerprint_html").generate(_ctx("tokA"))
    b = get_generator("fingerprint_html").generate(_ctx("tokA"))
    assert a.content == b.content


def test_fingerprint_html_differs_across_tokens() -> None:
    a = get_generator("fingerprint_html").generate(_ctx("tokA"))
    b = get_generator("fingerprint_html").generate(_ctx("tokB"))
    assert a.content != b.content


def test_fingerprint_html_notes_carry_mint_uuid_and_beacon() -> None:
    art = get_generator("fingerprint_html").generate(_ctx("tok-notes"))
    joined = " | ".join(art.notes)
    assert "mint_uuid=" in joined
    assert "https://canary.example.test/c/tok-notes" in joined


def test_fingerprint_svg_renders_valid_svg_with_script() -> None:
    art = get_generator("fingerprint_svg").generate(_ctx())
    body = art.content.decode("utf-8")
    assert body.startswith("<?xml version=\"1.0\"")
    assert "<svg" in body and "</svg>" in body
    assert "<script" in body and "<![CDATA[" in body
    assert art.mode == 0o644
    assert art.generator == "fingerprint_svg"


def test_fingerprint_svg_is_deterministic_per_token() -> None:
    a = get_generator("fingerprint_svg").generate(_ctx("svgTokA"))
    b = get_generator("fingerprint_svg").generate(_ctx("svgTokA"))
    assert a.content == b.content


def test_fingerprint_svg_differs_across_tokens() -> None:
    a = get_generator("fingerprint_svg").generate(_ctx("svgTokA"))
    b = get_generator("fingerprint_svg").generate(_ctx("svgTokB"))
    assert a.content != b.content


def test_mint_uuid_stable_across_html_and_svg() -> None:
    # Same callback token → same mint UUID across both generators, so
    # the worker can correlate beacons regardless of artifact shape.
    html = get_generator("fingerprint_html").generate(_ctx("shared-tok"))
    svg = get_generator("fingerprint_svg").generate(_ctx("shared-tok"))
    html_uuid = next(n for n in html.notes if n.startswith("mint_uuid="))
    svg_uuid = next(n for n in svg.notes if n.startswith("mint_uuid="))
    assert html_uuid == svg_uuid


def test_fingerprint_html_nonce_populated_and_matches_hmac() -> None:
    """Artifact carries ``fingerprint_nonce`` matching HMAC derivation."""
    import uuid as _uuid
    from decnet.canary.obfuscator import nonce_for

    art = get_generator("fingerprint_html").generate(_ctx("nonce-tok"))
    assert art.fingerprint_nonce is not None
    assert len(art.fingerprint_nonce) == 16
    _MINT_NS = _uuid.UUID("a3f7c821-9d1e-4b6a-8c2d-1e4f9a7b3c5d")
    expected_mint = str(_uuid.uuid5(_MINT_NS, "nonce-tok"))
    expected_nonce = nonce_for("nonce-tok", expected_mint)
    assert art.fingerprint_nonce == expected_nonce


def test_fingerprint_svg_nonce_matches_html_for_same_token() -> None:
    """Both generators derive the same nonce for the same callback token."""
    html = get_generator("fingerprint_html").generate(_ctx("nonce-tok2"))
    svg = get_generator("fingerprint_svg").generate(_ctx("nonce-tok2"))
    assert html.fingerprint_nonce == svg.fingerprint_nonce
