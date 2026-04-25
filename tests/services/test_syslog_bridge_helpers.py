"""Tests for shared emitter helpers in templates/syslog_bridge.py.

The canonical file is what gets propagated into per-template build
contexts via ``_sync_logging_helper``. This test file imports it
directly (not a per-service synced copy) so a regression in the
canonical surfaces immediately.
"""
from __future__ import annotations

import base64
import importlib.util
from pathlib import Path

import pytest


def _load_canonical():
    """Load the canonical templates/syslog_bridge.py as a module.

    The file isn't a package member (it lives under templates/, not
    decnet/), so we import via spec-from-path.
    """
    repo = Path(__file__).resolve().parents[2]
    path = repo / "decnet" / "templates" / "syslog_bridge.py"
    spec = importlib.util.spec_from_file_location("_canonical_syslog_bridge", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def syslog_bridge():
    return _load_canonical()


def test_encode_secret_ascii_passthrough(syslog_bridge):
    out = syslog_bridge.encode_secret("hunter2")
    assert out["secret_printable"] == "hunter2"
    assert base64.b64decode(out["secret_b64"]) == b"hunter2"


def test_encode_secret_collapses_nonprintables(syslog_bridge):
    """ANSI escape, NUL, 0xff bytes → '?' in printable form."""
    secret = "\x1b[31mbad\x00\xff trail"
    out = syslog_bridge.encode_secret(secret)
    # Original utf-8 bytes survive losslessly in b64.
    assert base64.b64decode(out["secret_b64"]) == secret.encode("utf-8", errors="replace")
    # Printable form has no control / high bytes.
    for ch in out["secret_printable"]:
        assert 0x20 <= ord(ch) < 0x7f


def test_encode_secret_empty(syslog_bridge):
    out = syslog_bridge.encode_secret("")
    assert out == {"secret_printable": "", "secret_b64": ""}


def test_encode_secret_preserves_rfc5424_specials(syslog_bridge):
    """Backslash / quote / bracket pass through to printable; sd_escape
    upstream is responsible for the literal RFC 5424 escape on the wire."""
    secret = 'a\\b"c]d'
    out = syslog_bridge.encode_secret(secret)
    assert out["secret_printable"] == 'a\\b"c]d'
    assert base64.b64decode(out["secret_b64"]) == secret.encode("utf-8")


def test_encode_secret_unicode_replaced(syslog_bridge):
    """Non-ASCII unicode encodes via utf-8, then printable strips the
    multi-byte sequence to '?' chars (one per raw byte)."""
    out = syslog_bridge.encode_secret("café")
    raw = "café".encode("utf-8")  # b'caf\xc3\xa9' — 5 bytes
    assert base64.b64decode(out["secret_b64"]) == raw
    # printable: 'c', 'a', 'f', '?', '?' — the two trailing utf-8 bytes
    # both fall outside [0x20, 0x7f).
    assert out["secret_printable"] == "caf??"
