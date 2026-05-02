"""
Tests for decnet/web/ingester.py

Covers log_ingestion_worker and _extract_bounty with
async tests using temporary files.
"""

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── _extract_bounty ───────────────────────────────────────────────────────────

class TestExtractBounty:
    @pytest.mark.asyncio
    async def test_credential_native_shape(self):
        """SSH/Telnet auth-helper shape (secret_b64) → upsert_credential."""
        from decnet.web.ingester import _extract_bounty
        import base64, hashlib
        mock_repo = MagicMock()
        mock_repo.upsert_credential = AsyncMock()
        log_data: dict = {
            "decky": "decky-01",
            "service": "ssh",
            "attacker_ip": "10.0.0.5",
            "fields": {
                "username": "root",
                "principal": "root",
                "secret_printable": "hunter2",
                "secret_b64": base64.b64encode(b"hunter2").decode(),
            },
        }
        await _extract_bounty(mock_repo, log_data)
        mock_repo.upsert_credential.assert_awaited_once()
        cred = mock_repo.upsert_credential.call_args[0][0]
        assert cred["service"] == "ssh"
        assert cred["principal"] == "root"
        assert cred["secret_sha256"] == hashlib.sha256(b"hunter2").hexdigest()

    @pytest.mark.asyncio
    async def test_credential_native_invalid_b64_dropped(self):
        """Malformed secret_b64 → row dropped with a warning, no upsert."""
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.upsert_credential = AsyncMock()
        log_data: dict = {
            "decky": "decky-01",
            "service": "ssh",
            "attacker_ip": "10.0.0.5",
            "fields": {"secret_b64": "not!base64!!"},
        }
        await _extract_bounty(mock_repo, log_data)
        mock_repo.upsert_credential.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_fields_skips(self):
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.upsert_credential = AsyncMock()
        await _extract_bounty(mock_repo, {"decky": "x"})
        mock_repo.upsert_credential.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_fields_not_dict_skips(self):
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.upsert_credential = AsyncMock()
        await _extract_bounty(mock_repo, {"fields": "not-a-dict"})
        mock_repo.upsert_credential.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_file_captured_emits_artifact_bounty(self):
        """SSH inotifywait `file_captured` event becomes a Bounty row of
        type=artifact so it shows on the global Vault page, not just on
        the per-attacker artifacts tab."""
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.upsert_credential = AsyncMock()
        await _extract_bounty(mock_repo, {
            "decky": "dmz-gateway",
            "service": "ssh",
            "attacker_ip": "31.56.209.39",
            "event_type": "file_captured",
            "fields": {
                "stored_as": "2026-04-28T22:35:58Z_abc123def456_evil.sh",
                "sha256": "deadbeef" * 8,
                "size": "1234",
                "orig_path": "/tmp/evil.sh",
                "attribution": "ssh-session-pid-940",
                "writer_comm": "bash",
            },
        })
        mock_repo.add_bounty.assert_awaited_once()
        bounty = mock_repo.add_bounty.call_args[0][0]
        assert bounty["bounty_type"] == "artifact"
        assert bounty["attacker_ip"] == "31.56.209.39"
        assert bounty["payload"]["kind"] == "file"
        assert bounty["payload"]["orig_path"] == "/tmp/evil.sh"
        assert bounty["payload"]["sha256"] == "deadbeef" * 8

    @pytest.mark.asyncio
    async def test_file_captured_without_stored_as_skipped(self):
        """A malformed file_captured row missing stored_as never lands in
        Bounty — sha256/size alone aren't enough to retrieve the bytes."""
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.upsert_credential = AsyncMock()
        await _extract_bounty(mock_repo, {
            "decky": "dmz-gateway",
            "service": "ssh",
            "attacker_ip": "1.2.3.4",
            "event_type": "file_captured",
            "fields": {"sha256": "abc", "size": "10"},
        })
        mock_repo.add_bounty.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_message_stored_emits_mail_artifact_bounty(self):
        """SMTP `message_stored` event lands as bounty_type=artifact with
        payload.kind=mail so the UI can render it with the Mail icon and
        subject/from preview rather than the file-drop layout."""
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.upsert_credential = AsyncMock()
        await _extract_bounty(mock_repo, {
            "decky": "mail-decky",
            "service": "smtp",
            "attacker_ip": "203.0.113.7",
            "event_type": "message_stored",
            "fields": {
                "stored_as": "2026-04-28T12:00:00Z_abc123def456_msg.eml",
                "sha256": "cafebabe" * 8,
                "size": "8192",
                "subject": "URGENT: invoice",
                "from_hdr": "billing@spammer.example",
                "to_hdr": "victim@target.tld",
                "mail_from": "spammer@spammer.example",
                "rcpt_to": "victim@target.tld",
                "attachment_count": "1",
                "content_type": "multipart/mixed",
            },
        })
        mock_repo.add_bounty.assert_awaited_once()
        bounty = mock_repo.add_bounty.call_args[0][0]
        assert bounty["bounty_type"] == "artifact"
        assert bounty["payload"]["kind"] == "mail"
        assert bounty["payload"]["subject"] == "URGENT: invoice"
        assert bounty["payload"]["mail_from"] == "spammer@spammer.example"

    @pytest.mark.asyncio
    async def test_message_stored_publishes_email_received(self):
        """SMTP message_stored persists the artifact AND publishes
        ``email.received`` with the EmailLifter wire contract: domains,
        rcpt_count + rcpt_domains, attachment shas + extensions, urls,
        dkim/spf bools, x_mailer."""
        from decnet.web import ingester as _ing
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.upsert_credential = AsyncMock()
        mock_repo.get_attacker_uuid_by_ip = AsyncMock(return_value="att-7")

        published: list = []

        async def fake_publish(_bus, topic, payload, event_type=""):
            published.append((topic, payload, event_type))

        fake_bus = MagicMock()
        fake_bus.connect = AsyncMock()
        fake_bus.close = AsyncMock()

        with patch.object(_ing, "get_bus", return_value=fake_bus), \
             patch.object(_ing, "publish_safely", side_effect=fake_publish):
            await _extract_bounty(mock_repo, {
                "decky": "mail-decky",
                "service": "smtp",
                "attacker_ip": "203.0.113.7",
                "event_type": "message_stored",
                "fields": {
                    "msg_id": "ABCD1234",
                    "stored_as": "2026-04-28T12:00:00Z_abc_msg.eml",
                    "sha256": "cafebabe" * 8,
                    "size": "8192",
                    "subject": "URGENT: invoice",
                    "from_hdr": '"CEO" <ceo@bigcorp.com>',
                    "to_hdr": "victim@target.tld",
                    "mail_from": "<spammer@evil.example>",
                    "rcpt_to": (
                        "victim1@target.tld, victim2@target.tld, "
                        "victim3@other.tld"
                    ),
                    "return_path": "<bounce@kit.evil>",
                    "x_mailer": "PHPMailer 6.0.7",
                    "dkim_signed": "1",
                    "spf_pass": "0",
                    "attachment_count": "2",
                    "attachments_json": (
                        '[{"filename":"payload.exe","sha256":"deadbeef",'
                        '"size":12,"content_type":"application/octet-stream"},'
                        '{"filename":"resume.docx","sha256":"feedface",'
                        '"size":34,"content_type":"application/msword"}]'
                    ),
                    "urls_json": (
                        '["https://xn--80ak6aa92e.example/login",'
                        '"http://kit.evil/payload.bin"]'
                    ),
                    "content_type": "multipart/mixed",
                },
            })

        # Bounty still lands.
        mock_repo.add_bounty.assert_awaited_once()
        # And exactly one email.received publish.
        email_publishes = [
            p for p in published
            if p[0].endswith("email.received")
        ]
        assert len(email_publishes) == 1
        topic, payload, event_type = email_publishes[0]
        assert event_type == "received"
        assert topic == "email.received"
        assert payload["attacker_uuid"] == "att-7"
        assert payload["from_domain"] == "bigcorp.com"
        assert payload["mail_from_domain"] == "evil.example"
        assert payload["return_path_domain"] == "kit.evil"
        assert payload["rcpt_count"] == 3
        assert payload["rcpt_domains"] == ["target.tld", "other.tld"]
        assert payload["x_mailer"] == "PHPMailer 6.0.7"
        assert payload["dkim_signed"] is True
        assert payload["spf_pass"] is False
        assert payload["urls"] == [
            "https://xn--80ak6aa92e.example/login",
            "http://kit.evil/payload.bin",
        ]
        assert payload["attachment_sha256s"] == ["deadbeef", "feedface"]
        assert payload["attachment_extensions"] == [".exe", ".docx"]
        assert payload["source_id"] == "ABCD1234"

    @pytest.mark.asyncio
    async def test_message_stored_projects_heavyweight_fields(self):
        """Layer-2 heavyweight fields land on the bus payload:
        body_simhash + body_base64_bytes (R0042 / R0048),
        attachment_macros + attachment_password_protected
        (R0046 macro / password lanes), html_smuggling (R0046 smuggling
        lane). Per-attachment manifest booleans reduce to top-level
        flags via OR."""
        from decnet.web import ingester as _ing
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.upsert_credential = AsyncMock()
        mock_repo.get_attacker_uuid_by_ip = AsyncMock(return_value="att-9")

        published: list = []

        async def fake_publish(_bus, topic, payload, event_type=""):
            published.append((topic, payload, event_type))

        fake_bus = MagicMock()
        fake_bus.connect = AsyncMock()
        fake_bus.close = AsyncMock()

        with patch.object(_ing, "get_bus", return_value=fake_bus), \
             patch.object(_ing, "publish_safely", side_effect=fake_publish):
            await _extract_bounty(mock_repo, {
                "decky": "mail-decky",
                "service": "smtp",
                "attacker_ip": "203.0.113.7",
                "event_type": "message_stored",
                "fields": {
                    "msg_id": "ABCD9999",
                    "stored_as": "2026-04-28T12:00:00Z_def_msg.eml",
                    "sha256": "babecafe" * 8,
                    "size": "12345",
                    "subject": "invoice",
                    "from_hdr": "ceo@bigcorp.com",
                    "to_hdr": "victim@target.tld",
                    "mail_from": "<spammer@evil.example>",
                    "rcpt_to": "victim@target.tld",
                    "attachment_count": "2",
                    "attachments_json": (
                        '[{"filename":"r.docm","sha256":"a","size":1,'
                        '"content_type":"application/vnd.ms-word.document.macroEnabled.12",'
                        '"macro_indicator":true,"encrypted":false},'
                        '{"filename":"s.zip","sha256":"b","size":2,'
                        '"content_type":"application/zip",'
                        '"macro_indicator":false,"encrypted":true}]'
                    ),
                    "urls_json": "[]",
                    "body_simhash": "deadbeefcafebabe",
                    "body_base64_bytes": 8192,
                    "html_smuggling": "1",
                    "content_type": "multipart/mixed",
                },
            })

        email_publishes = [
            p for p in published if p[0].endswith("email.received")
        ]
        assert len(email_publishes) == 1
        _topic, payload, _event_type = email_publishes[0]
        assert payload["body_simhash"] == "deadbeefcafebabe"
        assert payload["body_base64_bytes"] == 8192
        assert payload["attachment_macros"] is True
        assert payload["attachment_password_protected"] is True
        assert payload["html_smuggling"] is True

    @pytest.mark.asyncio
    async def test_message_stored_heavyweight_fields_safe_when_absent(self):
        """A pre-Layer-2 message_stored event (no simhash, no
        per-attachment booleans, no html_smuggling) projects to safe
        defaults: empty simhash, zero base64-bytes, all bools False."""
        from decnet.web import ingester as _ing
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.upsert_credential = AsyncMock()
        mock_repo.get_attacker_uuid_by_ip = AsyncMock(return_value="att-10")

        published: list = []

        async def fake_publish(_bus, topic, payload, event_type=""):
            published.append((topic, payload, event_type))

        fake_bus = MagicMock()
        fake_bus.connect = AsyncMock()
        fake_bus.close = AsyncMock()

        with patch.object(_ing, "get_bus", return_value=fake_bus), \
             patch.object(_ing, "publish_safely", side_effect=fake_publish):
            await _extract_bounty(mock_repo, {
                "decky": "old-decky",
                "service": "smtp",
                "attacker_ip": "10.0.0.99",
                "event_type": "message_stored",
                "fields": {
                    "stored_as": "x.eml",
                    "sha256": "h",
                    "size": "1",
                    "subject": "s",
                    "from_hdr": "a@b.c",
                    "to_hdr": "v@t.t",
                    "mail_from": "a@b.c",
                    "rcpt_to": "v@t.t",
                    "attachment_count": "0",
                    "content_type": "text/plain",
                    # No body_simhash / body_base64_bytes /
                    # html_smuggling / per-attachment manifest booleans.
                },
            })

        _topic, payload, _ = next(
            p for p in published if p[0].endswith("email.received")
        )
        assert payload["body_simhash"] == ""
        assert payload["body_base64_bytes"] == 0
        assert payload["attachment_macros"] is False
        assert payload["attachment_password_protected"] is False
        assert payload["html_smuggling"] is False

    @pytest.mark.asyncio
    async def test_message_stored_skips_publish_when_attacker_unresolved(self):
        """If get_attacker_uuid_by_ip returns None, no orphan
        email.received event lands."""
        from decnet.web import ingester as _ing
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.upsert_credential = AsyncMock()
        mock_repo.get_attacker_uuid_by_ip = AsyncMock(return_value=None)

        with patch.object(_ing, "get_bus") as p_bus, \
             patch.object(_ing, "publish_safely", new=AsyncMock()) as p_pub:
            await _extract_bounty(mock_repo, {
                "decky": "d",
                "service": "smtp",
                "attacker_ip": "10.0.0.1",
                "event_type": "message_stored",
                "fields": {
                    "stored_as": "x.eml",
                    "sha256": "h",
                    "size": "1",
                    "subject": "s",
                    "from_hdr": "a@b.c",
                    "to_hdr": "v@t.t",
                    "mail_from": "a@b.c",
                    "rcpt_to": "v@t.t",
                    "attachment_count": "0",
                    "content_type": "text/plain",
                },
            })
            mock_repo.add_bounty.assert_awaited_once()
            p_bus.assert_not_called()
            p_pub.assert_not_called()

    def test_domain_of_handles_common_shapes(self):
        from decnet.web.ingester import _domain_of
        assert _domain_of('"CEO" <ceo@bigcorp.com>') == "bigcorp.com"
        assert _domain_of("ceo@bigcorp.com") == "bigcorp.com"
        assert _domain_of("<a@b.com>") == "b.com"
        assert _domain_of("BIGCORP@EXAMPLE.COM") == "example.com"
        assert _domain_of("") is None
        assert _domain_of(None) is None
        assert _domain_of("no-at-sign-here") is None

    def test_attachment_extensions_unique_first_seen(self):
        from decnet.web.ingester import _attachment_extensions
        manifest = [
            {"filename": "a.EXE"},
            {"filename": "b.exe"},  # dedup'd against ".EXE"->".exe"
            {"filename": "noext"},
            {"filename": "report.pdf"},
            {"filename": "trailing."},  # dotless tail → skip
        ]
        assert _attachment_extensions(manifest) == [".exe", ".pdf"]

    def test_rcpt_projection_dedups_domains(self):
        from decnet.web.ingester import _rcpt_projection
        count, domains = _rcpt_projection(
            "a@x.com, b@x.com, c@y.com d@y.com",
        )
        # Whitespace-and-comma split gives 4 raw rcpts; domain set is 2.
        assert count == 4
        assert domains == ["x.com", "y.com"]

    @pytest.mark.asyncio
    async def test_no_secret_b64_no_credential(self):
        """The native branch keys off `secret_b64`. Fields lacking it
        produce no Credential row — even if username/password keys
        from the pre-migration era are present, they're now ignored."""
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.upsert_credential = AsyncMock()
        # Pre-migration shape — adapter is gone; this is a no-op path.
        await _extract_bounty(mock_repo, {
            "fields": {"username": "admin", "password": "stale"},
        })
        mock_repo.upsert_credential.assert_not_awaited()


# ── log_ingestion_worker ──────────────────────────────────────────────────────

class TestLogIngestionWorker:
    @pytest.mark.asyncio
    async def test_no_env_var_returns_immediately(self):
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        with patch.dict(os.environ, {}, clear=False):
            # Remove DECNET_INGEST_LOG_FILE if set
            os.environ.pop("DECNET_INGEST_LOG_FILE", None)
            await log_ingestion_worker(mock_repo)
            # Should return immediately without error

    @pytest.mark.asyncio
    async def test_file_not_exists_waits(self, tmp_path):
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_logs = AsyncMock()
        mock_repo.get_state = AsyncMock(return_value=None)
        mock_repo.set_state = AsyncMock()
        log_file = str(tmp_path / "nonexistent.log")
        _call_count: int = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": log_file}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=fake_sleep):
                with pytest.raises(asyncio.CancelledError):
                    await log_ingestion_worker(mock_repo)
        mock_repo.add_logs.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_ingests_json_lines(self, tmp_path):
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_logs = AsyncMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.get_state = AsyncMock(return_value=None)
        mock_repo.set_state = AsyncMock()

        log_file = str(tmp_path / "test.log")
        json_file = tmp_path / "test.json"
        json_file.write_text(
            json.dumps({"decky": "d1", "service": "ssh", "event_type": "auth",
                         "attacker_ip": "1.2.3.4", "fields": {}, "raw_line": "x", "msg": ""}) + "\n"
        )

        _call_count: int = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": log_file}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=fake_sleep):
                with pytest.raises(asyncio.CancelledError):
                    await log_ingestion_worker(mock_repo)

        mock_repo.add_logs.assert_awaited_once()
        _batch = mock_repo.add_logs.call_args[0][0]
        assert len(_batch) == 1
        assert _batch[0]["attacker_ip"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_handles_json_decode_error(self, tmp_path):
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_logs = AsyncMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.get_state = AsyncMock(return_value=None)
        mock_repo.set_state = AsyncMock()

        log_file = str(tmp_path / "test.log")
        json_file = tmp_path / "test.json"
        json_file.write_text("not valid json\n")

        _call_count: int = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": log_file}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=fake_sleep):
                with pytest.raises(asyncio.CancelledError):
                    await log_ingestion_worker(mock_repo)

        mock_repo.add_logs.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_file_truncation_resets_position(self, tmp_path):
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_logs = AsyncMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.get_state = AsyncMock(return_value=None)
        mock_repo.set_state = AsyncMock()

        log_file = str(tmp_path / "test.log")
        json_file = tmp_path / "test.json"

        _line: str = json.dumps({"decky": "d1", "service": "ssh", "event_type": "auth",
                                  "attacker_ip": "1.2.3.4", "fields": {}, "raw_line": "x", "msg": ""})
        # Write 2 lines, then truncate to 1
        json_file.write_text(_line + "\n" + _line + "\n")

        _call_count: int = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count == 2:
                # Simulate truncation
                json_file.write_text(_line + "\n")
            if _call_count >= 4:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": log_file}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=fake_sleep):
                with pytest.raises(asyncio.CancelledError):
                    await log_ingestion_worker(mock_repo)

        # Should have ingested lines from original + after truncation
        _total = sum(len(call.args[0]) for call in mock_repo.add_logs.call_args_list)
        assert _total >= 2

    @pytest.mark.asyncio
    async def test_partial_line_not_processed(self, tmp_path):
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_logs = AsyncMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.get_state = AsyncMock(return_value=None)
        mock_repo.set_state = AsyncMock()

        log_file = str(tmp_path / "test.log")
        json_file = tmp_path / "test.json"
        # Write a partial line (no newline at end)
        json_file.write_text('{"partial": true')

        _call_count: int = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": log_file}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=fake_sleep):
                with pytest.raises(asyncio.CancelledError):
                    await log_ingestion_worker(mock_repo)

        mock_repo.add_logs.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_position_restored_skips_already_seen_lines(self, tmp_path):
        """Worker resumes from saved position and skips already-ingested content."""
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_logs = AsyncMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.set_state = AsyncMock()

        log_file = str(tmp_path / "test.log")
        json_file = tmp_path / "test.json"

        line_old = json.dumps({"decky": "d1", "service": "ssh", "event_type": "auth",
                                "attacker_ip": "1.1.1.1", "fields": {}, "raw_line": "x", "msg": ""}) + "\n"
        line_new = json.dumps({"decky": "d2", "service": "ftp", "event_type": "auth",
                                "attacker_ip": "2.2.2.2", "fields": {}, "raw_line": "y", "msg": ""}) + "\n"

        json_file.write_text(line_old + line_new)

        # Saved position points to end of first line — only line_new should be ingested
        saved_position = len(line_old.encode("utf-8"))
        mock_repo.get_state = AsyncMock(return_value={"position": saved_position})

        _call_count: int = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": log_file}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=fake_sleep):
                with pytest.raises(asyncio.CancelledError):
                    await log_ingestion_worker(mock_repo)

        _rows = [r for call in mock_repo.add_logs.call_args_list for r in call.args[0]]
        assert len(_rows) == 1
        assert _rows[0]["attacker_ip"] == "2.2.2.2"

    @pytest.mark.asyncio
    async def test_set_state_called_with_position_after_batch(self, tmp_path):
        """set_state is called with the updated byte position after processing lines."""
        from decnet.web.ingester import log_ingestion_worker, _INGEST_STATE_KEY
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_logs = AsyncMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.get_state = AsyncMock(return_value=None)
        mock_repo.set_state = AsyncMock()

        log_file = str(tmp_path / "test.log")
        json_file = tmp_path / "test.json"
        line = json.dumps({"decky": "d1", "service": "ssh", "event_type": "auth",
                            "attacker_ip": "1.1.1.1", "fields": {}, "raw_line": "x", "msg": ""}) + "\n"
        json_file.write_text(line)

        _call_count: int = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": log_file}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=fake_sleep):
                with pytest.raises(asyncio.CancelledError):
                    await log_ingestion_worker(mock_repo)

        set_state_calls = mock_repo.set_state.call_args_list
        position_calls = [c for c in set_state_calls if c[0][0] == _INGEST_STATE_KEY]
        assert position_calls, "set_state never called with ingest position key"
        saved_pos = position_calls[-1][0][1]["position"]
        assert saved_pos == len(line.encode("utf-8"))

    @pytest.mark.asyncio
    async def test_batches_many_lines_into_few_commits(self, tmp_path):
        """250 lines with BATCH_SIZE=100 should flush in a handful of calls."""
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_logs = AsyncMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.get_state = AsyncMock(return_value=None)
        mock_repo.set_state = AsyncMock()

        log_file = str(tmp_path / "test.log")
        json_file = tmp_path / "test.json"
        _lines = "".join(
            json.dumps({
                "decky": f"d{i}", "service": "ssh", "event_type": "auth",
                "attacker_ip": f"10.0.0.{i % 256}", "fields": {}, "raw_line": "x", "msg": ""
            }) + "\n"
            for i in range(250)
        )
        json_file.write_text(_lines)

        _call_count: int = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": log_file}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=fake_sleep):
                with pytest.raises(asyncio.CancelledError):
                    await log_ingestion_worker(mock_repo)

        # 250 lines, batch=100 → 2 size-triggered flushes + 1 remainder flush.
        # Asserting <= 5 leaves headroom for time-triggered flushes on slow CI.
        assert mock_repo.add_logs.await_count <= 5
        _rows = [r for call in mock_repo.add_logs.call_args_list for r in call.args[0]]
        assert len(_rows) == 250

    @pytest.mark.asyncio
    async def test_truncation_resets_and_saves_zero_position(self, tmp_path):
        """On file truncation, set_state is called with position=0."""
        from decnet.web.ingester import log_ingestion_worker, _INGEST_STATE_KEY
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_logs = AsyncMock()
        mock_repo.add_bounty = AsyncMock()
        mock_repo.set_state = AsyncMock()

        log_file = str(tmp_path / "test.log")
        json_file = tmp_path / "test.json"

        line = json.dumps({"decky": "d1", "service": "ssh", "event_type": "auth",
                            "attacker_ip": "1.1.1.1", "fields": {}, "raw_line": "x", "msg": ""}) + "\n"
        # Pretend the saved position is past the end (simulates prior larger file)
        big_position = len(line.encode("utf-8")) * 10
        mock_repo.get_state = AsyncMock(return_value={"position": big_position})

        json_file.write_text(line)  # file is smaller than saved position → truncation

        _call_count: int = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        with patch.dict(os.environ, {"DECNET_INGEST_LOG_FILE": log_file}):
            with patch("decnet.web.ingester.asyncio.sleep", side_effect=fake_sleep):
                with pytest.raises(asyncio.CancelledError):
                    await log_ingestion_worker(mock_repo)

        reset_calls = [
            c for c in mock_repo.set_state.call_args_list
            if c[0][0] == _INGEST_STATE_KEY and c[0][1] == {"position": 0}
        ]
        assert reset_calls, "set_state not called with position=0 after truncation"
