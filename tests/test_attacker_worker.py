"""
Tests for decnet/web/attacker_worker.py

Covers:
- _cold_start(): full build on first run, cursor persistence
- _incremental_update(): delta processing, affected-IP-only updates
- _update_profiles(): traversal detection, bounty merging
- _extract_commands_from_events(): command harvesting from LogEvent objects
- _build_record(): record assembly from engine events + bounties
- _first_contact_deckies(): ordering for single-decky attackers
- attacker_profile_worker(): cancellation and error handling
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from decnet.correlation.parser import LogEvent
from decnet.logging.syslog_formatter import SEVERITY_INFO, format_rfc5424
from decnet.web.attacker_worker import (
    _BATCH_SIZE,
    _STATE_KEY,
    _WorkerState,
    _build_record,
    _cold_start,
    _extract_commands_from_events,
    _first_contact_deckies,
    _incremental_update,
    _update_profiles,
    attacker_profile_worker,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

_TS1 = "2026-04-04T10:00:00+00:00"
_TS2 = "2026-04-04T10:05:00+00:00"
_TS3 = "2026-04-04T10:10:00+00:00"

_DT1 = datetime.fromisoformat(_TS1)
_DT2 = datetime.fromisoformat(_TS2)
_DT3 = datetime.fromisoformat(_TS3)


def _make_raw_line(
    service: str = "ssh",
    hostname: str = "decky-01",
    event_type: str = "connection",
    src_ip: str = "1.2.3.4",
    timestamp: str = _TS1,
    **extra: str,
) -> str:
    return format_rfc5424(
        service=service,
        hostname=hostname,
        event_type=event_type,
        severity=SEVERITY_INFO,
        timestamp=datetime.fromisoformat(timestamp),
        src_ip=src_ip,
        **extra,
    )


def _make_log_row(
    row_id: int = 1,
    raw_line: str = "",
    attacker_ip: str = "1.2.3.4",
    service: str = "ssh",
    event_type: str = "connection",
    decky: str = "decky-01",
    timestamp: datetime = _DT1,
    fields: str = "{}",
) -> dict:
    if not raw_line:
        raw_line = _make_raw_line(
            service=service,
            hostname=decky,
            event_type=event_type,
            src_ip=attacker_ip,
            timestamp=timestamp.isoformat(),
        )
    return {
        "id": row_id,
        "raw_line": raw_line,
        "attacker_ip": attacker_ip,
        "service": service,
        "event_type": event_type,
        "decky": decky,
        "timestamp": timestamp,
        "fields": fields,
    }


def _make_repo(logs=None, bounties=None, bounties_for_ips=None, max_log_id=0, saved_state=None):
    repo = MagicMock()
    repo.get_all_logs_raw = AsyncMock(return_value=logs or [])
    repo.get_all_bounties_by_ip = AsyncMock(return_value=bounties or {})
    repo.get_bounties_for_ips = AsyncMock(return_value=bounties_for_ips or {})
    repo.get_max_log_id = AsyncMock(return_value=max_log_id)
    repo.get_logs_after_id = AsyncMock(return_value=[])
    repo.get_state = AsyncMock(return_value=saved_state)
    repo.set_state = AsyncMock()
    repo.upsert_attacker = AsyncMock()
    return repo


def _make_log_event(
    ip: str,
    decky: str,
    service: str = "ssh",
    event_type: str = "connection",
    timestamp: datetime = _DT1,
    fields: dict | None = None,
) -> LogEvent:
    return LogEvent(
        timestamp=timestamp,
        decky=decky,
        service=service,
        event_type=event_type,
        attacker_ip=ip,
        fields=fields or {},
        raw="",
    )


# ─── _first_contact_deckies ───────────────────────────────────────────────────

class TestFirstContactDeckies:
    def test_single_decky(self):
        events = [_make_log_event("1.1.1.1", "decky-01", timestamp=_DT1)]
        assert _first_contact_deckies(events) == ["decky-01"]

    def test_multiple_deckies_ordered_by_first_contact(self):
        events = [
            _make_log_event("1.1.1.1", "decky-02", timestamp=_DT2),
            _make_log_event("1.1.1.1", "decky-01", timestamp=_DT1),
        ]
        assert _first_contact_deckies(events) == ["decky-01", "decky-02"]

    def test_revisit_does_not_duplicate(self):
        events = [
            _make_log_event("1.1.1.1", "decky-01", timestamp=_DT1),
            _make_log_event("1.1.1.1", "decky-02", timestamp=_DT2),
            _make_log_event("1.1.1.1", "decky-01", timestamp=_DT3),  # revisit
        ]
        result = _first_contact_deckies(events)
        assert result == ["decky-01", "decky-02"]
        assert result.count("decky-01") == 1


# ─── _extract_commands_from_events ───────────────────────────────────────────

class TestExtractCommandsFromEvents:
    def test_extracts_command_field(self):
        events = [_make_log_event("1.1.1.1", "decky-01", "ssh", "command", _DT1, {"command": "id"})]
        result = _extract_commands_from_events(events)
        assert len(result) == 1
        assert result[0]["command"] == "id"
        assert result[0]["service"] == "ssh"
        assert result[0]["decky"] == "decky-01"

    def test_extracts_query_field(self):
        events = [_make_log_event("2.2.2.2", "decky-01", "mysql", "query", _DT1, {"query": "SELECT * FROM users"})]
        result = _extract_commands_from_events(events)
        assert len(result) == 1
        assert result[0]["command"] == "SELECT * FROM users"

    def test_extracts_input_field(self):
        events = [_make_log_event("3.3.3.3", "decky-01", "ssh", "input", _DT1, {"input": "ls -la"})]
        result = _extract_commands_from_events(events)
        assert len(result) == 1
        assert result[0]["command"] == "ls -la"

    def test_non_command_event_type_ignored(self):
        events = [_make_log_event("1.1.1.1", "decky-01", "ssh", "connection", _DT1, {"command": "id"})]
        result = _extract_commands_from_events(events)
        assert result == []

    def test_no_command_field_skipped(self):
        events = [_make_log_event("1.1.1.1", "decky-01", "ssh", "command", _DT1, {"other": "stuff"})]
        result = _extract_commands_from_events(events)
        assert result == []

    def test_multiple_commands_all_extracted(self):
        events = [
            _make_log_event("5.5.5.5", "decky-01", "ssh", "command", _DT1, {"command": "id"}),
            _make_log_event("5.5.5.5", "decky-01", "ssh", "command", _DT2, {"command": "uname -a"}),
        ]
        result = _extract_commands_from_events(events)
        assert len(result) == 2
        cmds = {r["command"] for r in result}
        assert cmds == {"id", "uname -a"}

    def test_timestamp_serialized_to_string(self):
        events = [_make_log_event("1.1.1.1", "decky-01", "ssh", "command", _DT1, {"command": "pwd"})]
        result = _extract_commands_from_events(events)
        assert isinstance(result[0]["timestamp"], str)


# ─── _build_record ────────────────────────────────────────────────────────────

class TestBuildRecord:
    def _events(self, ip="1.1.1.1"):
        return [
            _make_log_event(ip, "decky-01", "ssh", "conn", _DT1),
            _make_log_event(ip, "decky-01", "http", "req", _DT2),
        ]

    def test_basic_fields(self):
        events = self._events()
        record = _build_record("1.1.1.1", events, None, [], [])
        assert record["ip"] == "1.1.1.1"
        assert record["event_count"] == 2
        assert record["service_count"] == 2
        assert record["decky_count"] == 1

    def test_first_last_seen(self):
        events = self._events()
        record = _build_record("1.1.1.1", events, None, [], [])
        assert record["first_seen"] == _DT1
        assert record["last_seen"] == _DT2

    def test_services_json_sorted(self):
        events = self._events()
        record = _build_record("1.1.1.1", events, None, [], [])
        services = json.loads(record["services"])
        assert sorted(services) == services

    def test_no_traversal(self):
        events = self._events()
        record = _build_record("1.1.1.1", events, None, [], [])
        assert record["is_traversal"] is False
        assert record["traversal_path"] is None

    def test_with_traversal(self):
        from decnet.correlation.graph import AttackerTraversal, TraversalHop
        hops = [
            TraversalHop(_DT1, "decky-01", "ssh", "conn"),
            TraversalHop(_DT2, "decky-02", "http", "req"),
        ]
        t = AttackerTraversal("1.1.1.1", hops)
        events = [
            _make_log_event("1.1.1.1", "decky-01", timestamp=_DT1),
            _make_log_event("1.1.1.1", "decky-02", timestamp=_DT2),
        ]
        record = _build_record("1.1.1.1", events, t, [], [])
        assert record["is_traversal"] is True
        assert record["traversal_path"] == "decky-01 → decky-02"
        deckies = json.loads(record["deckies"])
        assert deckies == ["decky-01", "decky-02"]

    def test_bounty_counts(self):
        events = self._events()
        bounties = [
            {"bounty_type": "credential", "attacker_ip": "1.1.1.1"},
            {"bounty_type": "credential", "attacker_ip": "1.1.1.1"},
            {"bounty_type": "fingerprint", "attacker_ip": "1.1.1.1"},
        ]
        record = _build_record("1.1.1.1", events, None, bounties, [])
        assert record["bounty_count"] == 3
        assert record["credential_count"] == 2
        fps = json.loads(record["fingerprints"])
        assert len(fps) == 1
        assert fps[0]["bounty_type"] == "fingerprint"

    def test_commands_serialized(self):
        events = self._events()
        cmds = [{"service": "ssh", "decky": "decky-01", "command": "id", "timestamp": "2026-04-04T10:00:00"}]
        record = _build_record("1.1.1.1", events, None, [], cmds)
        parsed = json.loads(record["commands"])
        assert len(parsed) == 1
        assert parsed[0]["command"] == "id"

    def test_updated_at_is_utc_datetime(self):
        events = self._events()
        record = _build_record("1.1.1.1", events, None, [], [])
        assert isinstance(record["updated_at"], datetime)
        assert record["updated_at"].tzinfo is not None


# ─── _cold_start ─────────────────────────────────────────────────────────────

class TestColdStart:
    @pytest.mark.asyncio
    async def test_cold_start_builds_all_profiles(self):
        rows = [
            _make_log_row(
                row_id=i + 1,
                raw_line=_make_raw_line("ssh", "decky-01", "conn", ip, _TS1),
                attacker_ip=ip,
            )
            for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        ]
        repo = _make_repo(logs=rows, max_log_id=3)
        state = _WorkerState()

        await _cold_start(repo, state)

        assert state.initialized is True
        assert state.last_log_id == 3
        assert repo.upsert_attacker.await_count == 3
        upserted_ips = {c[0][0]["ip"] for c in repo.upsert_attacker.call_args_list}
        assert upserted_ips == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
        repo.set_state.assert_awaited_with(_STATE_KEY, {"last_log_id": 3})

    @pytest.mark.asyncio
    async def test_cold_start_empty_db(self):
        repo = _make_repo(logs=[], max_log_id=0)
        state = _WorkerState()

        await _cold_start(repo, state)

        assert state.initialized is True
        assert state.last_log_id == 0
        repo.upsert_attacker.assert_not_awaited()
        repo.set_state.assert_awaited()

    @pytest.mark.asyncio
    async def test_cold_start_traversal_detected(self):
        rows = [
            _make_log_row(
                row_id=1,
                raw_line=_make_raw_line("ssh", "decky-01", "conn", "5.5.5.5", _TS1),
                attacker_ip="5.5.5.5", decky="decky-01",
            ),
            _make_log_row(
                row_id=2,
                raw_line=_make_raw_line("http", "decky-02", "req", "5.5.5.5", _TS2),
                attacker_ip="5.5.5.5", decky="decky-02",
            ),
        ]
        repo = _make_repo(logs=rows, max_log_id=2)
        state = _WorkerState()

        await _cold_start(repo, state)

        record = repo.upsert_attacker.call_args[0][0]
        assert record["is_traversal"] is True
        assert "decky-01" in record["traversal_path"]
        assert "decky-02" in record["traversal_path"]

    @pytest.mark.asyncio
    async def test_cold_start_bounties_merged(self):
        raw = _make_raw_line("ssh", "decky-01", "conn", "8.8.8.8", _TS1)
        repo = _make_repo(
            logs=[_make_log_row(row_id=1, raw_line=raw, attacker_ip="8.8.8.8")],
            max_log_id=1,
            bounties_for_ips={"8.8.8.8": [
                {"bounty_type": "credential", "attacker_ip": "8.8.8.8", "payload": {}},
                {"bounty_type": "fingerprint", "attacker_ip": "8.8.8.8", "payload": {"ja3": "abc"}},
            ]},
        )
        state = _WorkerState()

        await _cold_start(repo, state)

        record = repo.upsert_attacker.call_args[0][0]
        assert record["bounty_count"] == 2
        assert record["credential_count"] == 1

    @pytest.mark.asyncio
    async def test_cold_start_commands_extracted(self):
        raw = _make_raw_line("ssh", "decky-01", "command", "9.9.9.9", _TS1, command="cat /etc/passwd")
        row = _make_log_row(
            row_id=1,
            raw_line=raw,
            attacker_ip="9.9.9.9",
            event_type="command",
            fields=json.dumps({"command": "cat /etc/passwd"}),
        )
        repo = _make_repo(logs=[row], max_log_id=1)
        state = _WorkerState()

        await _cold_start(repo, state)

        record = repo.upsert_attacker.call_args[0][0]
        commands = json.loads(record["commands"])
        assert len(commands) == 1
        assert commands[0]["command"] == "cat /etc/passwd"


# ─── _incremental_update ────────────────────────────────────────────────────

class TestIncrementalUpdate:
    @pytest.mark.asyncio
    async def test_no_new_logs_skips_upsert(self):
        repo = _make_repo()
        state = _WorkerState(initialized=True, last_log_id=10)

        await _incremental_update(repo, state)

        repo.upsert_attacker.assert_not_awaited()
        repo.set_state.assert_awaited_with(_STATE_KEY, {"last_log_id": 10})

    @pytest.mark.asyncio
    async def test_only_affected_ips_upserted(self):
        """Pre-populate engine with IP-A, then feed new logs only for IP-B."""
        state = _WorkerState(initialized=True, last_log_id=5)
        # Pre-populate engine with IP-A events
        line_a = _make_raw_line("ssh", "decky-01", "conn", "1.1.1.1", _TS1)
        state.engine.ingest(line_a)

        # New batch has only IP-B
        new_row = _make_log_row(
            row_id=6,
            raw_line=_make_raw_line("ssh", "decky-01", "conn", "2.2.2.2", _TS2),
            attacker_ip="2.2.2.2",
        )
        repo = _make_repo()
        repo.get_logs_after_id = AsyncMock(return_value=[new_row])

        await _incremental_update(repo, state)

        assert repo.upsert_attacker.await_count == 1
        upserted_ip = repo.upsert_attacker.call_args[0][0]["ip"]
        assert upserted_ip == "2.2.2.2"

    @pytest.mark.asyncio
    async def test_merges_with_existing_engine_state(self):
        """Engine has 2 events for IP. New batch adds 1 more. Record should show event_count=3."""
        state = _WorkerState(initialized=True, last_log_id=2)
        state.engine.ingest(_make_raw_line("ssh", "decky-01", "conn", "1.1.1.1", _TS1))
        state.engine.ingest(_make_raw_line("http", "decky-01", "req", "1.1.1.1", _TS2))

        new_row = _make_log_row(
            row_id=3,
            raw_line=_make_raw_line("ftp", "decky-01", "login", "1.1.1.1", _TS3),
            attacker_ip="1.1.1.1",
        )
        repo = _make_repo()
        repo.get_logs_after_id = AsyncMock(return_value=[new_row])

        await _incremental_update(repo, state)

        record = repo.upsert_attacker.call_args[0][0]
        assert record["event_count"] == 3
        assert record["ip"] == "1.1.1.1"

    @pytest.mark.asyncio
    async def test_cursor_persisted_after_update(self):
        new_row = _make_log_row(
            row_id=42,
            raw_line=_make_raw_line("ssh", "decky-01", "conn", "1.1.1.1", _TS1),
            attacker_ip="1.1.1.1",
        )
        repo = _make_repo()
        repo.get_logs_after_id = AsyncMock(return_value=[new_row])
        state = _WorkerState(initialized=True, last_log_id=41)

        await _incremental_update(repo, state)

        assert state.last_log_id == 42
        repo.set_state.assert_awaited_with(_STATE_KEY, {"last_log_id": 42})

    @pytest.mark.asyncio
    async def test_traversal_detected_across_cycles(self):
        """IP hits decky-01 during cold start, decky-02 in incremental → traversal."""
        state = _WorkerState(initialized=True, last_log_id=1)
        state.engine.ingest(_make_raw_line("ssh", "decky-01", "conn", "5.5.5.5", _TS1))

        new_row = _make_log_row(
            row_id=2,
            raw_line=_make_raw_line("http", "decky-02", "req", "5.5.5.5", _TS2),
            attacker_ip="5.5.5.5",
        )
        repo = _make_repo()
        repo.get_logs_after_id = AsyncMock(return_value=[new_row])

        await _incremental_update(repo, state)

        record = repo.upsert_attacker.call_args[0][0]
        assert record["is_traversal"] is True
        assert "decky-01" in record["traversal_path"]
        assert "decky-02" in record["traversal_path"]

    @pytest.mark.asyncio
    async def test_batch_loop_processes_all(self):
        """First batch returns BATCH_SIZE rows, second returns fewer — all processed."""
        batch_1 = [
            _make_log_row(
                row_id=i + 1,
                raw_line=_make_raw_line("ssh", "decky-01", "conn", f"10.0.0.{i}", _TS1),
                attacker_ip=f"10.0.0.{i}",
            )
            for i in range(_BATCH_SIZE)
        ]
        batch_2 = [
            _make_log_row(
                row_id=_BATCH_SIZE + 1,
                raw_line=_make_raw_line("ssh", "decky-01", "conn", "10.0.1.1", _TS2),
                attacker_ip="10.0.1.1",
            ),
        ]

        call_count = 0

        async def mock_get_logs(last_id, limit=_BATCH_SIZE):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return batch_1
            elif call_count == 2:
                return batch_2
            return []

        repo = _make_repo()
        repo.get_logs_after_id = AsyncMock(side_effect=mock_get_logs)
        state = _WorkerState(initialized=True, last_log_id=0)

        await _incremental_update(repo, state)

        assert state.last_log_id == _BATCH_SIZE + 1
        assert repo.upsert_attacker.await_count == _BATCH_SIZE + 1

    @pytest.mark.asyncio
    async def test_bounties_fetched_only_for_affected_ips(self):
        new_rows = [
            _make_log_row(
                row_id=1,
                raw_line=_make_raw_line("ssh", "decky-01", "conn", "1.1.1.1", _TS1),
                attacker_ip="1.1.1.1",
            ),
            _make_log_row(
                row_id=2,
                raw_line=_make_raw_line("ssh", "decky-01", "conn", "2.2.2.2", _TS2),
                attacker_ip="2.2.2.2",
            ),
        ]
        repo = _make_repo()
        repo.get_logs_after_id = AsyncMock(return_value=new_rows)
        state = _WorkerState(initialized=True, last_log_id=0)

        await _incremental_update(repo, state)

        repo.get_bounties_for_ips.assert_awaited_once()
        called_ips = repo.get_bounties_for_ips.call_args[0][0]
        assert called_ips == {"1.1.1.1", "2.2.2.2"}

    @pytest.mark.asyncio
    async def test_uninitialized_state_triggers_cold_start(self):
        rows = [
            _make_log_row(
                row_id=1,
                raw_line=_make_raw_line("ssh", "decky-01", "conn", "1.1.1.1", _TS1),
                attacker_ip="1.1.1.1",
            ),
        ]
        repo = _make_repo(logs=rows, max_log_id=1)
        state = _WorkerState()

        await _incremental_update(repo, state)

        assert state.initialized is True
        repo.get_all_logs_raw.assert_awaited_once()


# ─── attacker_profile_worker ────────────────────────────────────────────────

class TestAttackerProfileWorker:
    @pytest.mark.asyncio
    async def test_worker_cancels_cleanly(self):
        repo = _make_repo()
        task = asyncio.create_task(attacker_profile_worker(repo))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_worker_handles_update_error_without_crashing(self):
        repo = _make_repo()
        _call_count = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        async def bad_update(_repo, _state):
            raise RuntimeError("DB exploded")

        with patch("decnet.web.attacker_worker.asyncio.sleep", side_effect=fake_sleep):
            with patch("decnet.web.attacker_worker._incremental_update", side_effect=bad_update):
                with pytest.raises(asyncio.CancelledError):
                    await attacker_profile_worker(repo)

    @pytest.mark.asyncio
    async def test_worker_calls_update_after_sleep(self):
        repo = _make_repo()
        _call_count = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        update_calls = []

        async def mock_update(_repo, _state):
            update_calls.append(True)

        with patch("decnet.web.attacker_worker.asyncio.sleep", side_effect=fake_sleep):
            with patch("decnet.web.attacker_worker._incremental_update", side_effect=mock_update):
                with pytest.raises(asyncio.CancelledError):
                    await attacker_profile_worker(repo)

        assert len(update_calls) >= 1


# ─── JA3 bounty extraction from ingester ─────────────────────────────────────

class TestJA3BountyExtraction:
    @pytest.mark.asyncio
    async def test_ja3_bounty_extracted_from_sniffer_event(self):
        from decnet.web.ingester import _extract_bounty
        repo = MagicMock()
        repo.add_bounty = AsyncMock()
        log_data = {
            "decky": "decky-01",
            "service": "sniffer",
            "attacker_ip": "10.0.0.5",
            "event_type": "tls_client_hello",
            "fields": {
                "ja3": "abc123def456abc123def456abc12345",
                "ja3s": None,
                "tls_version": "TLS 1.3",
                "sni": "example.com",
                "alpn": "h2",
                "dst_port": "443",
                "raw_ciphers": "4865-4866",
                "raw_extensions": "0-23-65281",
            },
        }
        await _extract_bounty(repo, log_data)
        repo.add_bounty.assert_awaited_once()
        bounty = repo.add_bounty.call_args[0][0]
        assert bounty["bounty_type"] == "fingerprint"
        assert bounty["payload"]["fingerprint_type"] == "ja3"
        assert bounty["payload"]["ja3"] == "abc123def456abc123def456abc12345"
        assert bounty["payload"]["tls_version"] == "TLS 1.3"
        assert bounty["payload"]["sni"] == "example.com"

    @pytest.mark.asyncio
    async def test_non_sniffer_service_with_ja3_field_ignored(self):
        from decnet.web.ingester import _extract_bounty
        repo = MagicMock()
        repo.add_bounty = AsyncMock()
        log_data = {
            "service": "http",
            "attacker_ip": "10.0.0.6",
            "event_type": "request",
            "fields": {"ja3": "somehash"},
        }
        await _extract_bounty(repo, log_data)
        # Credential/UA checks run, but JA3 should not fire for non-sniffer
        calls = [c[0][0]["bounty_type"] for c in repo.add_bounty.call_args_list]
        assert "ja3" not in str(calls)

    @pytest.mark.asyncio
    async def test_sniffer_without_ja3_no_bounty(self):
        from decnet.web.ingester import _extract_bounty
        repo = MagicMock()
        repo.add_bounty = AsyncMock()
        log_data = {
            "service": "sniffer",
            "attacker_ip": "10.0.0.7",
            "event_type": "startup",
            "fields": {"msg": "started"},
        }
        await _extract_bounty(repo, log_data)
        repo.add_bounty.assert_not_awaited()
