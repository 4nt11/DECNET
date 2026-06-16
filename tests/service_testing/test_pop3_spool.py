# SPDX-License-Identifier: AGPL-3.0-or-later
"""Seed-backed email loading for the POP3 template.

Concat semantics: hardcoded ``_BAIT_EMAILS`` + .eml/.json from the seed
path.  Mirrors the IMAP test file.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

_HARDCODED = 10  # length of templates/pop3/server.py::_BAIT_EMAILS


_EML_TEMPLATE = (
    "From: Sender <sender@corp.com>\r\n"
    "To: Sarah <sarah@corp.com>\r\n"
    "Subject: {subject}\r\n"
    "Message-ID: <{mid}@corp.com>\r\n"
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


def _load_pop3(env_overrides):
    env = {
        "NODE_NAME": "testhost",
        "IMAP_USERS": "admin:admin123",
        **env_overrides,
    }
    for key in list(sys.modules):
        if key in ("pop3_server", "syslog_bridge"):
            del sys.modules[key]
    sys.modules["syslog_bridge"] = _make_fake_syslog_bridge()
    spec = importlib.util.spec_from_file_location(
        "pop3_server", "decnet/templates/pop3/server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", env, clear=False):
        spec.loader.exec_module(mod)
    return mod


def _seed(tmp_path: Path, n: int) -> Path:
    spool = tmp_path / "spool"
    spool.mkdir()
    for i in range(n):
        (spool / f"m{i}.eml").write_text(_EML_TEMPLATE.format(
            subject=f"Topic {i}", mid=f"m{i}", body=f"Body {i}",
        ))
    return spool


def test_falls_back_when_seed_unset(tmp_path):
    mod = _load_pop3({})
    assert len(mod._get_emails()) == _HARDCODED  # baseline only


def test_falls_back_when_seed_dir_missing(tmp_path):
    mod = _load_pop3({"POP3_EMAIL_SEED": str(tmp_path / "nope")})
    assert len(mod._get_emails()) == _HARDCODED


def test_seed_concatenates_with_hardcoded(tmp_path):
    spool = _seed(tmp_path, n=3)
    mod = _load_pop3({"POP3_EMAIL_SEED": str(spool)})
    emails = mod._get_emails()
    # Hardcoded baseline + 3 spooled .eml.
    assert len(emails) == _HARDCODED + 3
    # Hardcoded entries unchanged at the head.
    assert "AWS credentials rotation" in emails[0]
    # Seeded entries at the tail.
    assert any("Topic 0" in e for e in emails[_HARDCODED:])
    assert all(e.startswith("From:") for e in emails[_HARDCODED:])


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
            # Missing 'subject' — skipped, not fatal.
            "from_addr": "ghost@corp.com",
            "to_addr": "admin@corp.com",
            "body": "no subject",
        },
    ]))
    mod = _load_pop3({"POP3_EMAIL_SEED": str(seed)})
    emails = mod._get_emails()
    assert len(emails) == _HARDCODED + 1
    seeded = emails[-1]
    assert "Subject: Q4 numbers" in seeded
    assert "From: CEO <ceo@corp.com>" in seeded


def test_stat_reflects_concatenated_count(tmp_path):
    spool = _seed(tmp_path, n=2)
    mod = _load_pop3({"POP3_EMAIL_SEED": str(spool)})
    proto = mod.POP3Protocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    written.clear()
    proto.data_received(b"USER admin\r\n")
    proto.data_received(b"PASS admin123\r\n")
    written.clear()
    proto.data_received(b"STAT\r\n")
    out = b"".join(written)
    expected = _HARDCODED + 2
    assert out.startswith(f"+OK {expected} ".encode())
