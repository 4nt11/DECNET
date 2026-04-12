"""
Tests for decnet/web/ingester.py

Covers log_ingestion_worker and _extract_bounty with
async tests using temporary files.
"""

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── _extract_bounty ───────────────────────────────────────────────────────────

class TestExtractBounty:
    @pytest.mark.asyncio
    async def test_credential_extraction(self):
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        log_data: dict = {
            "decky": "decky-01",
            "service": "ssh",
            "attacker_ip": "10.0.0.5",
            "fields": {"username": "admin", "password": "hunter2"},
        }
        await _extract_bounty(mock_repo, log_data)
        mock_repo.add_bounty.assert_awaited_once()
        bounty = mock_repo.add_bounty.call_args[0][0]
        assert bounty["bounty_type"] == "credential"
        assert bounty["payload"]["username"] == "admin"
        assert bounty["payload"]["password"] == "hunter2"

    @pytest.mark.asyncio
    async def test_no_fields_skips(self):
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        await _extract_bounty(mock_repo, {"decky": "x"})
        mock_repo.add_bounty.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_fields_not_dict_skips(self):
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        await _extract_bounty(mock_repo, {"fields": "not-a-dict"})
        mock_repo.add_bounty.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_missing_password_skips(self):
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        await _extract_bounty(mock_repo, {"fields": {"username": "admin"}})
        mock_repo.add_bounty.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_missing_username_skips(self):
        from decnet.web.ingester import _extract_bounty
        mock_repo = MagicMock()
        mock_repo.add_bounty = AsyncMock()
        await _extract_bounty(mock_repo, {"fields": {"password": "pass"}})
        mock_repo.add_bounty.assert_not_awaited()


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
        mock_repo.add_log.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_ingests_json_lines(self, tmp_path):
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_bounty = AsyncMock()

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

        mock_repo.add_log.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_handles_json_decode_error(self, tmp_path):
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_bounty = AsyncMock()

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

        mock_repo.add_log.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_file_truncation_resets_position(self, tmp_path):
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_bounty = AsyncMock()

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
        assert mock_repo.add_log.await_count >= 2

    @pytest.mark.asyncio
    async def test_partial_line_not_processed(self, tmp_path):
        from decnet.web.ingester import log_ingestion_worker
        mock_repo = MagicMock()
        mock_repo.add_log = AsyncMock()
        mock_repo.add_bounty = AsyncMock()

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

        mock_repo.add_log.assert_not_awaited()
