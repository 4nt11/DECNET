"""Disk-reach tests for EmailLifter (DEBT-047).

When the bus payload omits ``body_text`` but carries ``decky_id`` +
``stored_as``, body-aware predicates (R0047 BEC, encoded-payload) must
open the stored ``.eml`` from the artifact tree and parse the body
in-process. Bus carries only the pointer; raw body bytes stay on
host disk.
"""

from __future__ import annotations

from email.message import EmailMessage

import pytest

from decnet.artifacts import paths as artifact_paths
from decnet.ttp.impl import email_lifter as lifter_mod


_DECKY = "test-decky-01"
_STORED_AS = "2026-04-18T02:22:56Z_abc123def456_msg.eml"


def _write_eml(root, body_text, *, content_type="text/plain"):
    msg = EmailMessage()
    msg["From"] = "alice@evil.example"
    msg["To"] = "victim@target.example"
    msg["Subject"] = "URGENT: wire transfer needed"
    if content_type == "text/plain":
        msg.set_content(body_text)
    else:
        msg.set_content("plain fallback")
        msg.add_alternative(body_text, subtype="html")
    smtp_dir = root / _DECKY / "smtp"
    smtp_dir.mkdir(parents=True, exist_ok=True)
    p = smtp_dir / _STORED_AS
    p.write_bytes(bytes(msg))
    return p


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setattr(artifact_paths, "ARTIFACTS_ROOT", tmp_path)
    return tmp_path


_BEC_SPEC = {
    "subject_keywords": ["wire transfer", "urgent"],
    "body_action_keywords": ["bank", "iban", "account"],
}


def test_p_bec_matches_via_disk_reach(root):
    _write_eml(
        root, "Please update our bank account / IBAN before EOD.",
    )
    payload = {
        "subject": "URGENT: wire transfer needed",
        "decky_id": _DECKY,
        "stored_as": _STORED_AS,
    }
    result = lifter_mod._p_bec(_BEC_SPEC, payload)
    assert result is not None
    assert result["matched_subject_kw"] == "wire transfer"
    assert result["matched_body_kw"] in {"bank", "iban"}
    # Helper must have memoized the body back into the payload.
    assert "bank" in payload["body_text"].lower()


def test_p_bec_no_match_when_eml_missing(root):
    payload = {
        "subject": "URGENT: wire transfer needed",
        "decky_id": _DECKY,
        "stored_as": _STORED_AS,
    }
    assert lifter_mod._p_bec(_BEC_SPEC, payload) is None


def test_p_bec_no_match_without_pointer(root):
    payload = {"subject": "URGENT: wire transfer needed"}
    assert lifter_mod._p_bec(_BEC_SPEC, payload) is None


def test_inline_body_text_takes_precedence(root, monkeypatch):
    """If the producer ships body_text inline, no file IO happens."""
    sentinel = "Please remit IBAN bank details now."
    payload = {
        "subject": "URGENT: wire transfer needed",
        "body_text": sentinel,
        "decky_id": _DECKY,
        "stored_as": _STORED_AS,
    }

    def _explode(*a, **kw):
        raise AssertionError("disk-reach must not run when body_text inline")

    monkeypatch.setattr(lifter_mod, "resolve_artifact_path", _explode)
    res = lifter_mod._p_bec(_BEC_SPEC, payload)
    assert res is not None


def test_body_cache_avoids_second_open(root, monkeypatch):
    _write_eml(root, "wire to our bank IBAN now")
    opens: list[str] = []
    real_open = lifter_mod.email.message_from_binary_file

    def _spy(fh, *a, **kw):
        opens.append("opened")
        return real_open(fh, *a, **kw)

    monkeypatch.setattr(
        lifter_mod.email, "message_from_binary_file", _spy,
    )
    payload = {
        "subject": "URGENT: wire transfer needed",
        "decky_id": _DECKY,
        "stored_as": _STORED_AS,
    }
    lifter_mod._p_bec(_BEC_SPEC, payload)
    lifter_mod._p_bec(_BEC_SPEC, payload)
    assert len(opens) == 1


def test_html_fallback_when_no_text_plain(tmp_path, monkeypatch):
    monkeypatch.setattr(artifact_paths, "ARTIFACTS_ROOT", tmp_path)
    smtp = tmp_path / _DECKY / "smtp"
    smtp.mkdir(parents=True)
    raw = (
        b"From: a@b\r\nTo: c@d\r\nSubject: t\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><body>please send our IBAN bank info</body></html>"
    )
    (smtp / _STORED_AS).write_bytes(raw)
    payload = {
        "subject": "URGENT: wire transfer needed",
        "decky_id": _DECKY,
        "stored_as": _STORED_AS,
    }
    result = lifter_mod._p_bec(_BEC_SPEC, payload)
    assert result is not None


def test_invalid_pointer_rejected(root):
    """Bad decky/stored_as values must not crash and must yield no body."""
    payload = {
        "subject": "URGENT: wire transfer needed",
        "decky_id": "../etc",
        "stored_as": _STORED_AS,
    }
    assert lifter_mod._p_bec(_BEC_SPEC, payload) is None
