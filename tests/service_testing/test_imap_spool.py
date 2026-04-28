"""Spool-backed email loading for the IMAP template.

Verifies that when ``IMAP_EMAIL_SEED`` points at a directory of .eml
files, the IMAP server serves those (replacing the hardcoded
``_BAIT_EMAILS`` fallback).  Empty / missing dir falls back gracefully.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest


_EML_TEMPLATE = (
    "From: {from_name} <{from_addr}>\r\n"
    "To: Sarah <sarah@corp.com>\r\n"
    "Subject: {subject}\r\n"
    "Message-ID: <{mid}@corp.com>\r\n"
    "Date: Mon, 26 Apr 2026 10:00:00 +0000\r\n"
    "\r\n"
    "{body}\r\n"
)


def _make_fake_syslog_bridge() -> ModuleType:
    mod = ModuleType("syslog_bridge")
    mod.syslog_line = MagicMock(return_value="")
    mod.write_syslog_file = MagicMock()
    mod.forward_syslog = MagicMock()
    mod.SEVERITY_WARNING = 4
    mod.SEVERITY_INFO = 6
    mod.encode_secret = MagicMock(return_value={"secret_printable": "", "secret_b64": ""})
    mod.classify_authorization = MagicMock(return_value=None)
    return mod


def _load_imap(env_overrides: dict[str, str]):
    env = {
        "NODE_NAME": "testhost",
        "IMAP_USERS": "admin:admin123",
        "IMAP_BANNER": "* OK Dovecot ready.",
        **env_overrides,
    }
    for key in list(sys.modules):
        if key in ("imap_server", "syslog_bridge"):
            del sys.modules[key]
    sys.modules["syslog_bridge"] = _make_fake_syslog_bridge()
    spec = importlib.util.spec_from_file_location(
        "imap_server", "decnet/templates/imap/server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", env, clear=False):
        spec.loader.exec_module(mod)
    return mod


def _seed(tmp_path: Path, n: int = 3) -> Path:
    spool = tmp_path / "spool"
    spool.mkdir()
    thread = spool / "thr1"
    thread.mkdir()
    for i in range(n):
        eml = thread / f"msg{i}.eml"
        eml.write_text(_EML_TEMPLATE.format(
            from_name=f"Sender {i}",
            from_addr=f"sender{i}@corp.com",
            subject=f"Topic {i}",
            mid=f"m{i}",
            body=f"Body of message {i}.",
        ))
    return spool


def test_falls_back_to_hardcoded_when_seed_unset(tmp_path):
    mod = _load_imap({})
    emails = mod._get_emails()
    # The shipped fallback ships exactly 10 entries.
    assert len(emails) == 10
    assert emails[0]["from_addr"] == "devops@company.internal"


def test_falls_back_when_seed_dir_missing(tmp_path):
    mod = _load_imap({"IMAP_EMAIL_SEED": str(tmp_path / "does-not-exist")})
    emails = mod._get_emails()
    assert len(emails) == 10  # fallback


def test_falls_back_when_seed_dir_empty(tmp_path):
    (tmp_path / "spool").mkdir()
    mod = _load_imap({"IMAP_EMAIL_SEED": str(tmp_path / "spool")})
    assert len(mod._get_emails()) == 10  # fallback (no .eml files)


def test_loads_eml_files_from_spool(tmp_path):
    spool = _seed(tmp_path, n=3)
    mod = _load_imap({"IMAP_EMAIL_SEED": str(spool)})
    emails = mod._get_emails()
    assert len(emails) == 3
    senders = {e["from_addr"] for e in emails}
    assert senders == {"sender0@corp.com", "sender1@corp.com", "sender2@corp.com"}
    # UIDs are 1-based and unique.
    assert {e["uid"] for e in emails} == {1, 2, 3}


def test_loaded_eml_carries_full_rfc822_body(tmp_path):
    spool = _seed(tmp_path, n=1)
    mod = _load_imap({"IMAP_EMAIL_SEED": str(spool)})
    emails = mod._get_emails()
    assert "From:" in emails[0]["body"]
    assert "Subject: Topic 0" in emails[0]["body"]
    assert "Body of message 0." in emails[0]["body"]


def test_corrupt_eml_skipped_not_fatal(tmp_path):
    spool = tmp_path / "spool"
    spool.mkdir()
    (spool / "good.eml").write_text(_EML_TEMPLATE.format(
        from_name="Good", from_addr="good@corp.com",
        subject="ok", mid="g", body="ok",
    ))
    # Make a directory with a .eml extension to provoke an OSError on
    # read_bytes — the loader should skip it without crashing.
    (spool / "broken.eml").mkdir()
    mod = _load_imap({"IMAP_EMAIL_SEED": str(spool)})
    emails = mod._get_emails()
    assert len(emails) == 1
    assert emails[0]["from_addr"] == "good@corp.com"


def test_select_inbox_reflects_spool_count(tmp_path):
    spool = _seed(tmp_path, n=4)
    mod = _load_imap({"IMAP_EMAIL_SEED": str(spool)})
    proto = mod.IMAPProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    written.clear()
    proto.data_received(b"A0 LOGIN admin admin123\r\n")
    written.clear()
    proto.data_received(b"B0 SELECT INBOX\r\n")
    out = b"".join(written)
    assert b"* 4 EXISTS" in out
    assert b"[UIDNEXT 5]" in out
