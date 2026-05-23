# SPDX-License-Identifier: AGPL-3.0-or-later
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


def test_classify_authorization_basic(syslog_bridge):
    """HTTP Basic — base64(user:pw) decodes to plaintext credential."""
    cred = syslog_bridge.classify_authorization("Basic YWRtaW46aHVudGVyMg==")
    assert cred is not None
    assert cred["principal"] == "admin"
    assert cred["secret_kind"] == "plaintext"
    assert base64.b64decode(cred["secret_b64"]) == b"hunter2"
    assert cred["secret_printable"] == "hunter2"


def test_classify_authorization_bearer(syslog_bridge):
    cred = syslog_bridge.classify_authorization("Bearer eyJhbGciOiJIUzI1NiJ9.foo.bar")
    assert cred["principal"] is None
    assert cred["secret_kind"] == "http_bearer"
    assert base64.b64decode(cred["secret_b64"]) == b"eyJhbGciOiJIUzI1NiJ9.foo.bar"


def test_classify_authorization_token_alias(syslog_bridge):
    """`Token <opaque>` = same shape as Bearer (Kubernetes service accounts)."""
    cred = syslog_bridge.classify_authorization("Token sa-jwt-token-abc")
    assert cred["secret_kind"] == "http_bearer"


def test_classify_authorization_digest(syslog_bridge):
    """RFC 7616 Digest — extract username + response hash."""
    header = ('Digest username="alice", realm="example.com", '
              'nonce="abc123", uri="/", response="d41d8cd98f00b204e9800998ecf8427e"')
    cred = syslog_bridge.classify_authorization(header)
    assert cred["principal"] == "alice"
    assert cred["secret_kind"] == "http_digest_md5"
    assert cred["secret_printable"] == "d41d8cd98f00b204e9800998ecf8427e"


def test_classify_authorization_unknown_scheme(syslog_bridge):
    """NTLM, AWS4-HMAC-…, Negotiate — all return None for now."""
    assert syslog_bridge.classify_authorization("NTLM TlRMTVNTUAA=") is None
    assert syslog_bridge.classify_authorization("AWS4-HMAC-SHA256 Credential=…") is None


def test_extract_form_credentials_wordpress(syslog_bridge):
    """wp-login.php uses `log` for username and `pwd` for password."""
    body = "log=admin&pwd=hunter2&wp-submit=Log+In"
    cred = syslog_bridge.extract_form_credentials(
        body, "application/x-www-form-urlencoded"
    )
    assert cred["principal"] == "admin"
    assert cred["secret_kind"] == "plaintext"
    assert cred["secret_printable"] == "hunter2"


def test_extract_form_credentials_standard(syslog_bridge):
    body = "username=admin&password=hunter2"
    cred = syslog_bridge.extract_form_credentials(
        body, "application/x-www-form-urlencoded"
    )
    assert cred["principal"] == "admin"
    assert cred["secret_kind"] == "plaintext"
    assert cred["secret_printable"] == "hunter2"


def test_extract_form_credentials_secret_without_principal(syslog_bridge):
    """Secret-only forms (rare but seen — password reset confirms,
    auto-fill abuse) still capture as a credential. principal=None
    means we couldn't pin down the user, but the secret hash is still
    cross-correlatable for reuse analytics."""
    body = "password=hunter2&csrf=abc"
    cred = syslog_bridge.extract_form_credentials(
        body, "application/x-www-form-urlencoded"
    )
    assert cred is not None
    assert cred["principal"] is None
    assert cred["secret_printable"] == "hunter2"


def test_extract_form_credentials_alternate_keys(syslog_bridge):
    cred = syslog_bridge.extract_form_credentials(
        "user=alice&pwd=h%40ck", "application/x-www-form-urlencoded"
    )
    assert cred["principal"] == "alice"
    assert cred["secret_printable"] == "h@ck"  # %40 decoded


def test_extract_form_credentials_wrong_content_type(syslog_bridge):
    """Don't try to parse JSON / multipart / etc bodies."""
    assert syslog_bridge.extract_form_credentials(
        "username=admin&password=x", "application/json"
    ) is None
    assert syslog_bridge.extract_form_credentials(
        "username=admin&password=x", None
    ) is None


def test_extract_form_credentials_no_secret(syslog_bridge):
    """Username only → no cred row (need both principal + secret)."""
    cred = syslog_bridge.extract_form_credentials(
        "username=admin&csrf_token=xyz", "application/x-www-form-urlencoded"
    )
    assert cred is None


def test_classify_authorization_malformed(syslog_bridge):
    assert syslog_bridge.classify_authorization(None) is None
    assert syslog_bridge.classify_authorization("") is None
    assert syslog_bridge.classify_authorization("Basic !!not-base64!!") is None
    assert syslog_bridge.classify_authorization("Basic dXNlcg==") is None  # no colon
    assert syslog_bridge.classify_authorization("Digest no-response-here") is None


def test_encode_secret_unicode_replaced(syslog_bridge):
    """Non-ASCII unicode encodes via utf-8, then printable strips the
    multi-byte sequence to '?' chars (one per raw byte)."""
    out = syslog_bridge.encode_secret("café")
    raw = "café".encode("utf-8")  # b'caf\xc3\xa9' — 5 bytes
    assert base64.b64decode(out["secret_b64"]) == raw
    # printable: 'c', 'a', 'f', '?', '?' — the two trailing utf-8 bytes
    # both fall outside [0x20, 0x7f).
    assert out["secret_printable"] == "caf??"
