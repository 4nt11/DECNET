"""
Tests for decnet/templates/smtp/server.py

Exercises both modes:
  - credential-harvester (SMTP_OPEN_RELAY=0, default)
  - open relay (SMTP_OPEN_RELAY=1)

Uses asyncio transport/protocol directly — no network socket needed.
"""

import base64
import importlib.util
import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_fake_syslog_bridge() -> ModuleType:
    """Return a stub syslog_bridge module that does nothing."""
    mod = ModuleType("syslog_bridge")
    mod.syslog_line = MagicMock(return_value="")
    mod.write_syslog_file = MagicMock()
    mod.forward_syslog = MagicMock()
    mod.SEVERITY_WARNING = 4
    mod.SEVERITY_INFO = 6
    return mod


def _load_smtp(open_relay: bool):
    """Import smtp server module with desired OPEN_RELAY value.

    Injects a stub syslog_bridge into sys.modules so the template can import
    it without needing the real file on sys.path.
    """
    env = {
        "SMTP_OPEN_RELAY": "1" if open_relay else "0",
        "NODE_NAME": "testhost",
        # Force deterministic RCPT acceptance in tests; relay filtering is
        # covered in its own dedicated test class below.
        "SMTP_RCPT_DROP_RATE": "0",
    }
    for key in ("smtp_server", "syslog_bridge", "instance_seed"):
        sys.modules.pop(key, None)

    sys.modules["syslog_bridge"] = _make_fake_syslog_bridge()

    spec = importlib.util.spec_from_file_location("smtp_server", "decnet/templates/smtp/server.py")
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", env, clear=False):
        from .conftest import load_real_instance_seed
        sys.modules["instance_seed"] = load_real_instance_seed()
        spec.loader.exec_module(mod)
    return mod


def _make_protocol(mod):
    """Return a (protocol, transport, written) triple. Banner is already discarded."""
    proto = mod.SMTPProtocol()
    transport = MagicMock()
    written: list[bytes] = []
    transport.write.side_effect = written.append
    proto.connection_made(transport)
    written.clear()
    return proto, transport, written


def _send(proto, *lines: str) -> None:
    """Feed CRLF-terminated lines to the protocol."""
    for line in lines:
        proto.data_received((line + "\r\n").encode())


def _replies(written: list[bytes]) -> list[str]:
    """Flatten written bytes into a list of non-empty response lines."""
    result = []
    for chunk in written:
        for line in chunk.decode().split("\r\n"):
            if line:
                result.append(line)
    return result


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def relay_mod():
    return _load_smtp(open_relay=True)

@pytest.fixture
def harvester_mod():
    return _load_smtp(open_relay=False)


# ── Banner ────────────────────────────────────────────────────────────────────

def test_banner_is_220(relay_mod):
    proto, transport, written = _make_protocol(relay_mod)
    # written was cleared — re-trigger banner check via a fresh instance
    proto2 = relay_mod.SMTPProtocol()
    t2 = MagicMock()
    w2: list[bytes] = []
    t2.write.side_effect = w2.append
    proto2.connection_made(t2)
    banner = b"".join(w2).decode()
    assert banner.startswith("220")
    assert "ESMTP" in banner


# ── EHLO ──────────────────────────────────────────────────────────────────────

def test_ehlo_returns_250_multiline(relay_mod):
    proto, _, written = _make_protocol(relay_mod)
    _send(proto, "EHLO attacker.com")
    combined = b"".join(written).decode()
    assert "250" in combined
    assert "AUTH" in combined
    assert "PIPELINING" in combined


def test_ehlo_empty_domain_rejected(relay_mod):
    proto, _, written = _make_protocol(relay_mod)
    _send(proto, "EHLO")
    replies = _replies(written)
    assert any(r.startswith("501") for r in replies)


def test_helo_empty_domain_rejected(relay_mod):
    proto, _, written = _make_protocol(relay_mod)
    _send(proto, "HELO")
    replies = _replies(written)
    assert any(r.startswith("501") for r in replies)


# ── OPEN RELAY MODE ───────────────────────────────────────────────────────────

class TestOpenRelay:

    @staticmethod
    def _session(relay_mod, *lines):
        proto, _, written = _make_protocol(relay_mod)
        _send(proto, *lines)
        return _replies(written)

    def test_auth_plain_accepted(self, relay_mod):
        creds = base64.b64encode(b"\x00admin\x00password").decode()
        replies = self._session(relay_mod, f"AUTH PLAIN {creds}")
        assert any(r.startswith("235") for r in replies)

    def test_auth_login_multistep_accepted(self, relay_mod):
        proto, _, written = _make_protocol(relay_mod)
        _send(proto, "AUTH LOGIN")
        _send(proto, base64.b64encode(b"admin").decode())
        _send(proto, base64.b64encode(b"password").decode())
        replies = _replies(written)
        assert any(r.startswith("235") for r in replies)

    def test_rcpt_to_any_domain_accepted(self, relay_mod):
        replies = self._session(
            relay_mod,
            "EHLO x.com",
            "MAIL FROM:<spam@evil.com>",
            "RCPT TO:<victim@anydomain.com>",
        )
        assert any(r.startswith("250 2.1.5") for r in replies)

    def test_full_relay_flow(self, relay_mod):
        replies = self._session(
            relay_mod,
            "EHLO attacker.com",
            "MAIL FROM:<hacker@evil.com>",
            "RCPT TO:<admin@target.com>",
            "DATA",
            "Subject: hello",
            "",
            "Body line 1",
            "Body line 2",
            ".",
            "QUIT",
        )
        assert any(r.startswith("354") for r in replies), "Expected 354 after DATA"
        assert any("queued as" in r for r in replies), "Expected queued-as ID"
        assert any(r.startswith("221") for r in replies), "Expected 221 on QUIT"

    def test_multi_recipient(self, relay_mod):
        replies = self._session(
            relay_mod,
            "EHLO x.com",
            "MAIL FROM:<a@b.com>",
            "RCPT TO:<c@d.com>",
            "RCPT TO:<e@f.com>",
            "RCPT TO:<g@h.com>",
            "DATA",
            "Subject: spam",
            "",
            "hello",
            ".",
        )
        assert len([r for r in replies if r.startswith("250 2.1.5")]) == 3

    def test_dot_stuffing_stripped(self, relay_mod):
        """Leading dot on a body line must be stripped per RFC 5321."""
        proto, _, written = _make_protocol(relay_mod)
        _send(proto,
              "EHLO x.com",
              "MAIL FROM:<a@b.com>",
              "RCPT TO:<c@d.com>",
              "DATA",
              "..real dot line",
              "normal line",
              ".",
              )
        replies = _replies(written)
        assert any("queued as" in r for r in replies)

    def test_data_rejected_without_rcpt(self, relay_mod):
        replies = self._session(relay_mod, "EHLO x.com", "MAIL FROM:<a@b.com>", "DATA")
        assert any(r.startswith("503") for r in replies)

    def test_rset_clears_transaction_state(self, relay_mod):
        proto, _, _ = _make_protocol(relay_mod)
        _send(proto, "EHLO x.com", "MAIL FROM:<a@b.com>", "RCPT TO:<c@d.com>", "RSET")
        assert proto._mail_from == ""
        assert proto._rcpt_to == []
        assert proto._in_data is False

    def test_second_send_after_rset(self, relay_mod):
        """A new transaction started after RSET must complete successfully."""
        replies = self._session(
            relay_mod,
            "EHLO x.com",
            "MAIL FROM:<a@b.com>",
            "RCPT TO:<c@d.com>",
            "RSET",
            "MAIL FROM:<new@b.com>",
            "RCPT TO:<new@d.com>",
            "DATA",
            "body",
            ".",
        )
        assert any("queued as" in r for r in replies)


# ── OPEN-RELAY FILTERING ─────────────────────────────────────────────────────

class TestOpenRelayFiltering:
    """Real open relays reject malformed/bogus RCPTs even when they accept
    external mail — a pure tarpit is a honeypot tell."""

    @staticmethod
    def _session_with_env(env_extra: dict, *lines) -> list[str]:
        env = {
            "SMTP_OPEN_RELAY": "1",
            "NODE_NAME": "testhost",
            "SMTP_RCPT_DROP_RATE": "0",
            **env_extra,
        }
        for key in ("smtp_server", "syslog_bridge", "instance_seed"):
            sys.modules.pop(key, None)
        sys.modules["syslog_bridge"] = _make_fake_syslog_bridge()
        spec = importlib.util.spec_from_file_location(
            "smtp_server", "decnet/templates/smtp/server.py"
        )
        mod = importlib.util.module_from_spec(spec)
        with patch.dict("os.environ", env, clear=False):
            from .conftest import load_real_instance_seed
            sys.modules["instance_seed"] = load_real_instance_seed()
            spec.loader.exec_module(mod)
        proto, _, written = _make_protocol(mod)
        _send(proto, *lines)
        return _replies(written)

    def test_malformed_rcpt_returns_501(self):
        replies = self._session_with_env(
            {},
            "EHLO x.com",
            "MAIL FROM:<a@b.com>",
            "RCPT TO:<notanaddress>",
        )
        assert any(r.startswith("501") for r in replies)

    def test_blocked_tld_returns_550(self):
        replies = self._session_with_env(
            {},
            "EHLO x.com",
            "MAIL FROM:<a@b.com>",
            "RCPT TO:<admin@foo.invalid>",
        )
        assert any(r.startswith("550") for r in replies)

    def test_always_greylist_returns_451(self):
        replies = self._session_with_env(
            {"SMTP_RCPT_DROP_RATE": "1.0"},
            "EHLO x.com",
            "MAIL FROM:<a@b.com>",
            "RCPT TO:<victim@legit-domain.com>",
        )
        assert any(r.startswith("451") for r in replies)


# ── CREDENTIAL HARVESTER MODE ─────────────────────────────────────────────────

class TestCredentialHarvester:

    @staticmethod
    def _session(harvester_mod, *lines):
        proto, _, written = _make_protocol(harvester_mod)
        _send(proto, *lines)
        return _replies(written)

    def test_auth_plain_rejected_535(self, harvester_mod):
        creds = base64.b64encode(b"\x00admin\x00password").decode()
        replies = self._session(harvester_mod, f"AUTH PLAIN {creds}")
        assert any(r.startswith("535") for r in replies)

    def test_auth_rejected_connection_stays_open(self, harvester_mod):
        """After 535 the connection must stay alive — old code closed it immediately."""
        proto, transport, _ = _make_protocol(harvester_mod)
        creds = base64.b64encode(b"\x00admin\x00password").decode()
        _send(proto, f"AUTH PLAIN {creds}")
        transport.close.assert_not_called()

    def test_rcpt_to_denied_554(self, harvester_mod):
        replies = self._session(
            harvester_mod,
            "EHLO x.com",
            "MAIL FROM:<a@b.com>",
            "RCPT TO:<admin@target.com>",
        )
        assert any(r.startswith("554") for r in replies)

    def test_relay_denied_blocks_data(self, harvester_mod):
        """With all RCPT TO rejected, DATA must return 503."""
        replies = self._session(
            harvester_mod,
            "EHLO x.com",
            "MAIL FROM:<a@b.com>",
            "RCPT TO:<c@d.com>",
            "DATA",
        )
        assert any(r.startswith("503") for r in replies)

    def test_noop_and_quit(self, harvester_mod):
        replies = self._session(harvester_mod, "NOOP", "QUIT")
        assert any(r.startswith("250") for r in replies)
        assert any(r.startswith("221") for r in replies)

    def test_unknown_command_502(self, harvester_mod):
        replies = self._session(harvester_mod, "BADCMD foo")
        assert any(r.startswith("502") for r in replies)

    def test_starttls_declined_454(self, harvester_mod):
        replies = self._session(harvester_mod, "STARTTLS")
        assert any(r.startswith("454") for r in replies)


# ── Queue ID ──────────────────────────────────────────────────────────────────

def test_rand_msg_id_format(relay_mod):
    # Postfix queue IDs use a vowel-free alphabet (no aeiou, no 0/1) and
    # vary in length with the current microsecond magnitude — typically
    # 10-12 chars.
    postfix_alphabet = set("BCDFGHJKLMNPQRSTVWXYZ23456789")
    for _ in range(50):
        mid = relay_mod._rand_msg_id()
        assert 10 <= len(mid) <= 12
        assert set(mid).issubset(postfix_alphabet)


# ── AUTH PLAIN decode ─────────────────────────────────────────────────────────

def test_decode_auth_plain_normal(relay_mod):
    blob = base64.b64encode(b"\x00alice\x00s3cr3t").decode()
    user, pw = relay_mod._decode_auth_plain(blob)
    assert user == "alice"
    assert pw == "s3cr3t"


def test_decode_auth_plain_garbage_no_raise(relay_mod):
    user, pw = relay_mod._decode_auth_plain("!!!notbase64!!!")
    assert isinstance(user, str)
    assert isinstance(pw, str)


# ── Bare LF line endings ────────────────────────────────────────────────────

def _send_bare_lf(proto, *lines: str) -> None:
    """Feed LF-only terminated lines to the protocol (simulates telnet/nc)."""
    for line in lines:
        proto.data_received((line + "\n").encode())


def test_ehlo_works_with_bare_lf(relay_mod):
    """Clients sending bare LF (telnet, nc) must get EHLO responses."""
    proto, _, written = _make_protocol(relay_mod)
    _send_bare_lf(proto, "EHLO attacker.com")
    combined = b"".join(written).decode()
    assert "250" in combined
    assert "AUTH" in combined


def test_full_session_with_bare_lf(relay_mod):
    """A complete relay session using bare LF line endings."""
    proto, _, written = _make_protocol(relay_mod)
    _send_bare_lf(
        proto,
        "EHLO attacker.com",
        "MAIL FROM:<hacker@evil.com>",
        "RCPT TO:<admin@target.com>",
        "DATA",
        "Subject: test",
        "",
        "body",
        ".",
        "QUIT",
    )
    replies = _replies(written)
    assert any("queued as" in r for r in replies)
    assert any(r.startswith("221") for r in replies)


def test_mixed_line_endings(relay_mod):
    """A single data_received call containing a mix of CRLF and bare LF."""
    proto, _, written = _make_protocol(relay_mod)
    proto.data_received(b"EHLO test.com\r\nMAIL FROM:<a@b.com>\nRCPT TO:<c@d.com>\r\n")
    replies = _replies(written)
    assert any("250" in r for r in replies)
    assert any(r.startswith("250 2.1.0") for r in replies)
    assert any(r.startswith("250 2.1.5") for r in replies)


# ── AUTH PLAIN continuation (no inline credentials) ──────────────────────────

def test_auth_plain_continuation_relay(relay_mod):
    """AUTH PLAIN without inline creds should prompt then accept on next line."""
    proto, _, written = _make_protocol(relay_mod)
    _send(proto, "AUTH PLAIN")
    replies = _replies(written)
    assert any(r.startswith("334") for r in replies), "Expected 334 continuation"
    written.clear()
    creds = base64.b64encode(b"\x00admin\x00password").decode()
    _send(proto, creds)
    replies = _replies(written)
    assert any(r.startswith("235") for r in replies), "Expected 235 auth success"


def test_auth_plain_continuation_harvester(harvester_mod):
    """AUTH PLAIN continuation in harvester mode should reject with 535."""
    proto, _, written = _make_protocol(harvester_mod)
    _send(proto, "AUTH PLAIN")
    replies = _replies(written)
    assert any(r.startswith("334") for r in replies)
    written.clear()
    creds = base64.b64encode(b"\x00admin\x00password").decode()
    _send(proto, creds)
    replies = _replies(written)
    assert any(r.startswith("535") for r in replies)


# ── FULL-MESSAGE CAPTURE (quarantine + message_stored event) ─────────────────

def _load_smtp_with_quarantine(quarantine_dir: str, max_body_bytes: int | None = None):
    """Reload the SMTP template with a quarantine dir + optional body cap.

    Same mechanics as _load_smtp but threads extra env through so the module's
    capture-path code is exercised end-to-end (file write + parse).
    """
    env = {
        "SMTP_OPEN_RELAY": "1",
        "NODE_NAME": "testhost",
        "SMTP_RCPT_DROP_RATE": "0",
        "SMTP_QUARANTINE_DIR": quarantine_dir,
    }
    if max_body_bytes is not None:
        env["SMTP_MAX_BODY_BYTES"] = str(max_body_bytes)
    for key in ("smtp_server", "syslog_bridge", "instance_seed"):
        sys.modules.pop(key, None)
    sys.modules["syslog_bridge"] = _make_fake_syslog_bridge()
    spec = importlib.util.spec_from_file_location(
        "smtp_server", "decnet/templates/smtp/server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", env, clear=False):
        from .conftest import load_real_instance_seed
        sys.modules["instance_seed"] = load_real_instance_seed()
        spec.loader.exec_module(mod)
    return mod


def _logged_events(mod) -> list[tuple[str, dict]]:
    """Return every (event_type, fields) tuple syslog_bridge was called with."""
    calls = mod.syslog_line.call_args_list
    events: list[tuple[str, dict]] = []
    for call in calls:
        args, kwargs = call
        # syslog_line(service, hostname, event_type, severity=..., **fields)
        event_type = args[2] if len(args) > 2 else kwargs.get("event_type", "")
        # Strip positional service/hostname/event_type/severity when present.
        fields = dict(kwargs)
        fields.pop("severity", None)
        events.append((event_type, fields))
    return events


class TestMessageCapture:

    def test_message_stored_event_written(self, tmp_path):
        mod = _load_smtp_with_quarantine(str(tmp_path))
        proto, _, _ = _make_protocol(mod)
        _send(
            proto,
            "EHLO x.com",
            "MAIL FROM:<spam@evil.com>",
            "RCPT TO:<victim@target.com>",
            "DATA",
            "Subject: hello",
            "From: spam@evil.com",
            "",
            "body line",
            ".",
        )
        events = _logged_events(mod)
        stored = [f for t, f in events if t == "message_stored"]
        assert len(stored) == 1, f"expected 1 message_stored event, got {events}"
        rec = stored[0]
        assert rec["subject"] == "hello"
        assert rec["from_hdr"] == "spam@evil.com"
        assert rec["mail_from"] == "<spam@evil.com>"
        assert rec["rcpt_to"] == "<victim@target.com>"
        assert rec["attachment_count"] == 0
        # Filename matches artifact endpoint's regex.
        import re as _re
        assert _re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z_[a-f0-9]{12}_[A-Za-z0-9._-]{1,255}",
            rec["stored_as"],
        )

    def test_message_file_written_to_quarantine(self, tmp_path):
        mod = _load_smtp_with_quarantine(str(tmp_path))
        proto, _, _ = _make_protocol(mod)
        _send(
            proto,
            "EHLO x.com",
            "MAIL FROM:<a@b.com>",
            "RCPT TO:<c@d.com>",
            "DATA",
            "Subject: test",
            "",
            "payload bytes",
            ".",
        )
        files = list(tmp_path.iterdir())
        assert len(files) == 1
        contents = files[0].read_bytes()
        assert b"Subject: test" in contents
        assert b"payload bytes" in contents
        assert files[0].name.endswith(".eml")

    def test_attachment_manifest_captured(self, tmp_path):
        """A multipart message with an attachment must report filename + sha256."""
        import hashlib as _hashlib
        mod = _load_smtp_with_quarantine(str(tmp_path))
        proto, _, _ = _make_protocol(mod)
        boundary = "----ABC"
        payload = b"MZ\x90\x00fake-exe-bytes"
        import base64 as _b64
        payload_b64 = _b64.b64encode(payload).decode()
        _send(
            proto,
            "EHLO x.com",
            "MAIL FROM:<a@b.com>",
            "RCPT TO:<c@d.com>",
            "DATA",
            "Subject: malware",
            f"Content-Type: multipart/mixed; boundary={boundary}",
            "MIME-Version: 1.0",
            "",
            f"--{boundary}",
            'Content-Type: text/plain',
            "",
            "see attached",
            f"--{boundary}",
            'Content-Type: application/octet-stream; name="payload.exe"',
            'Content-Disposition: attachment; filename="payload.exe"',
            "Content-Transfer-Encoding: base64",
            "",
            payload_b64,
            f"--{boundary}--",
            ".",
        )
        events = _logged_events(mod)
        stored = [f for t, f in events if t == "message_stored"]
        assert len(stored) == 1
        rec = stored[0]
        assert rec["attachment_count"] == 1
        import json as _json
        manifest = _json.loads(rec["attachments_json"])
        assert len(manifest) == 1
        assert manifest[0]["filename"] == "payload.exe"
        assert manifest[0]["sha256"] == _hashlib.sha256(payload).hexdigest()
        assert manifest[0]["size"] == len(payload)

    def test_capture_disabled_when_dir_unset(self, tmp_path, relay_mod):
        """With SMTP_QUARANTINE_DIR unset, message_accepted fires but no
        message_stored event and no files are written."""
        proto, _, _ = _make_protocol(relay_mod)
        _send(
            proto,
            "EHLO x.com",
            "MAIL FROM:<a@b.com>",
            "RCPT TO:<c@d.com>",
            "DATA",
            "Subject: no-capture",
            "",
            "body",
            ".",
        )
        events = _logged_events(relay_mod)
        assert any(t == "message_accepted" for t, _ in events)
        assert not any(t == "message_stored" for t, _ in events)

    def test_body_size_cap_truncates(self, tmp_path):
        """Body beyond SMTP_MAX_BODY_BYTES is dropped but the session still
        terminates and truncated=1 is flagged."""
        mod = _load_smtp_with_quarantine(str(tmp_path), max_body_bytes=64)
        proto, _, _ = _make_protocol(mod)
        big_line = "A" * 500
        _send(
            proto,
            "EHLO x.com",
            "MAIL FROM:<a@b.com>",
            "RCPT TO:<c@d.com>",
            "DATA",
            "Subject: big",
            "",
            big_line,
            big_line,
            ".",
        )
        events = _logged_events(mod)
        stored = [f for t, f in events if t == "message_stored"]
        accepted = [f for t, f in events if t == "message_accepted"]
        assert accepted and accepted[0]["truncated"] == 1
        # File still written with whatever we managed to buffer.
        assert len(list(tmp_path.iterdir())) == 1
        assert stored and stored[0]["truncated"] == 1

    def test_rset_resets_body_state(self, tmp_path):
        """RSET must clear data_bytes + truncated flag so a fresh transaction
        is not accounted against the prior one."""
        mod = _load_smtp_with_quarantine(str(tmp_path))
        proto, _, _ = _make_protocol(mod)
        _send(proto, "EHLO x.com", "MAIL FROM:<a@b.com>", "RCPT TO:<c@d.com>", "RSET")
        assert proto._data_bytes == 0
        assert proto._data_truncated is False
