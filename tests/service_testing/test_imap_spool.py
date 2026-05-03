"""Seed-backed email loading for the IMAP template.

Verifies that when ``IMAP_EMAIL_SEED`` points at a directory of .eml /
.json (or a single .json / .eml), the IMAP server CONCATENATES those
entries onto the hardcoded ``_BAIT_EMAILS`` baseline.  Empty / missing
input falls back to the baseline alone — the realism-engine output and
operator-curated seeds are additive, never replacing.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

_HARDCODED = 10  # length of templates/imap/server.py::_BAIT_EMAILS


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
    # The shipped baseline is exactly 10 entries.
    assert len(emails) == _HARDCODED
    assert emails[0]["from_addr"] == "devops@company.internal"


def test_falls_back_when_seed_dir_missing(tmp_path):
    mod = _load_imap({"IMAP_EMAIL_SEED": str(tmp_path / "does-not-exist")})
    emails = mod._get_emails()
    assert len(emails) == _HARDCODED  # baseline only


def test_falls_back_when_seed_dir_empty(tmp_path):
    (tmp_path / "spool").mkdir()
    mod = _load_imap({"IMAP_EMAIL_SEED": str(tmp_path / "spool")})
    assert len(mod._get_emails()) == _HARDCODED  # baseline only


def test_seed_concatenates_with_hardcoded(tmp_path):
    spool = _seed(tmp_path, n=3)
    mod = _load_imap({"IMAP_EMAIL_SEED": str(spool)})
    emails = mod._get_emails()
    # Hardcoded 10 + 3 spooled = 13.
    assert len(emails) == _HARDCODED + 3
    # Hardcoded baseline keeps original UIDs 1..10.
    assert emails[0]["uid"] == 1
    assert emails[0]["from_addr"] == "devops@company.internal"
    assert emails[9]["uid"] == 10
    # Seeded entries pick up at UID 11.
    assert {e["uid"] for e in emails[10:]} == {11, 12, 13}
    senders = {e["from_addr"] for e in emails[10:]}
    assert senders == {"sender0@corp.com", "sender1@corp.com", "sender2@corp.com"}


def test_loaded_eml_carries_full_rfc822_body(tmp_path):
    spool = _seed(tmp_path, n=1)
    mod = _load_imap({"IMAP_EMAIL_SEED": str(spool)})
    emails = mod._get_emails()
    seeded = emails[_HARDCODED]
    assert "From:" in seeded["body"]
    assert "Subject: Topic 0" in seeded["body"]
    assert "Body of message 0." in seeded["body"]


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
    assert len(emails) == _HARDCODED + 1
    assert emails[-1]["from_addr"] == "good@corp.com"


def test_json_seed_file_loaded(tmp_path):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps([
        {
            "from_addr": "ceo@corp.com",
            "from_name": "CEO",
            "to_addr": "admin@corp.com",
            "subject": "Q4 numbers",
            "date": "Mon, 27 Apr 2026 09:00:00 +0000",
            "body": "Please review attached.",
        },
        {
            # Missing 'subject' — must be skipped, not crash.
            "from_addr": "ghost@corp.com",
            "to_addr": "admin@corp.com",
            "body": "no subject",
        },
    ]))
    mod = _load_imap({"IMAP_EMAIL_SEED": str(seed)})
    emails = mod._get_emails()
    assert len(emails) == _HARDCODED + 1  # one valid, one dropped
    seeded = emails[-1]
    assert seeded["uid"] == _HARDCODED + 1
    assert seeded["from_addr"] == "ceo@corp.com"
    # JSON entry without RFC 822 headers gets wrapped into a full message.
    assert "From: CEO <ceo@corp.com>" in seeded["body"]
    assert "Subject: Q4 numbers" in seeded["body"]


def test_dir_with_eml_and_json_concatenated(tmp_path):
    spool = _seed(tmp_path, n=2)
    (spool / "extra.json").write_text(json.dumps([
        {
            "from_addr": "ops@corp.com",
            "to_addr": "admin@corp.com",
            "subject": "extra",
            "body": "hi",
        },
    ]))
    mod = _load_imap({"IMAP_EMAIL_SEED": str(spool)})
    emails = mod._get_emails()
    # Hardcoded + 2 .eml + 1 .json
    assert len(emails) == _HARDCODED + 3


def test_select_inbox_reflects_concatenated_count(tmp_path):
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
    expected_total = _HARDCODED + 4
    assert f"* {expected_total} EXISTS".encode() in out
    assert f"[UIDNEXT {expected_total + 1}]".encode() in out
