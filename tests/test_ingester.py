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
