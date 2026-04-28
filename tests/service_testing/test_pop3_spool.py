"""Spool-backed email loading for the POP3 template."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch


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
    assert len(mod._get_emails()) == 10  # hardcoded fallback


def test_falls_back_when_seed_dir_missing(tmp_path):
    mod = _load_pop3({"POP3_EMAIL_SEED": str(tmp_path / "nope")})
    assert len(mod._get_emails()) == 10


def test_loads_emls_from_spool(tmp_path):
    spool = _seed(tmp_path, n=3)
    mod = _load_pop3({"POP3_EMAIL_SEED": str(spool)})
    emails = mod._get_emails()
    assert len(emails) == 3
    # POP3 stores raw RFC 822 strings; verify content round-trips.
    assert any("Topic 0" in e for e in emails)
    assert all(e.startswith("From:") for e in emails)


def test_stat_reflects_spool_size(tmp_path):
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
    assert out.startswith(b"+OK 2 ")
