"""
Tests for decnet/web/attacker_worker.py

Covers:
- _rebuild(): CorrelationEngine integration, traversal detection, upsert calls
- _extract_commands(): command harvesting from raw log rows
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

from decnet.logging.syslog_formatter import SEVERITY_INFO, format_rfc5424
from decnet.web.attacker_worker import (
    _build_record,
    _extract_commands,
    _first_contact_deckies,
    _rebuild,
    attacker_profile_worker,
)
from decnet.correlation.parser import LogEvent

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
        "id": 1,
        "raw_line": raw_line,
        "attacker_ip": attacker_ip,
        "service": service,
        "event_type": event_type,
        "decky": decky,
        "timestamp": timestamp,
        "fields": fields,
    }


def _make_repo(logs=None, bounties=None):
    repo = MagicMock()
    repo.get_all_logs_raw = AsyncMock(return_value=logs or [])
    repo.get_all_bounties_by_ip = AsyncMock(return_value=bounties or {})
    repo.upsert_attacker = AsyncMock()
    return repo


def _make_log_event(
    ip: str,
    decky: str,
    service: str = "ssh",
    event_type: str = "connection",
    timestamp: datetime = _DT1,
) -> LogEvent:
    return LogEvent(
        timestamp=timestamp,
        decky=decky,
        service=service,
        event_type=event_type,
        attacker_ip=ip,
        fields={},
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


# ─── _extract_commands ────────────────────────────────────────────────────────

class TestExtractCommands:
    def _row(self, ip, event_type, fields):
        return _make_log_row(
            attacker_ip=ip,
            event_type=event_type,
            service="ssh",
            decky="decky-01",
            fields=json.dumps(fields),
        )

    def test_extracts_command_field(self):
        rows = [self._row("1.1.1.1", "command", {"command": "id"})]
        result = _extract_commands(rows, "1.1.1.1")
        assert len(result) == 1
        assert result[0]["command"] == "id"
        assert result[0]["service"] == "ssh"
        assert result[0]["decky"] == "decky-01"

    def test_extracts_query_field(self):
        rows = [self._row("2.2.2.2", "query", {"query": "SELECT * FROM users"})]
        result = _extract_commands(rows, "2.2.2.2")
        assert len(result) == 1
        assert result[0]["command"] == "SELECT * FROM users"

    def test_extracts_input_field(self):
        rows = [self._row("3.3.3.3", "input", {"input": "ls -la"})]
        result = _extract_commands(rows, "3.3.3.3")
        assert len(result) == 1
        assert result[0]["command"] == "ls -la"

    def test_non_command_event_type_ignored(self):
        rows = [self._row("1.1.1.1", "connection", {"command": "id"})]
        result = _extract_commands(rows, "1.1.1.1")
        assert result == []

    def test_wrong_ip_ignored(self):
        rows = [self._row("9.9.9.9", "command", {"command": "whoami"})]
        result = _extract_commands(rows, "1.1.1.1")
        assert result == []

    def test_no_command_field_skipped(self):
        rows = [self._row("1.1.1.1", "command", {"other": "stuff"})]
        result = _extract_commands(rows, "1.1.1.1")
        assert result == []

    def test_invalid_json_fields_skipped(self):
        row = _make_log_row(
            attacker_ip="1.1.1.1",
            event_type="command",
            fields="not valid json",
        )
        result = _extract_commands([row], "1.1.1.1")
        assert result == []

    def test_multiple_commands_all_extracted(self):
        rows = [
            self._row("5.5.5.5", "command", {"command": "id"}),
            self._row("5.5.5.5", "command", {"command": "uname -a"}),
        ]
        result = _extract_commands(rows, "5.5.5.5")
        assert len(result) == 2
        cmds = {r["command"] for r in result}
        assert cmds == {"id", "uname -a"}

    def test_timestamp_serialized_to_string(self):
        rows = [self._row("1.1.1.1", "command", {"command": "pwd"})]
        result = _extract_commands(rows, "1.1.1.1")
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


# ─── _rebuild ─────────────────────────────────────────────────────────────────

class TestRebuild:
    @pytest.mark.asyncio
    async def test_empty_logs_no_upsert(self):
        repo = _make_repo(logs=[])
        await _rebuild(repo)
        repo.upsert_attacker.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_single_attacker_upserted(self):
        raw = _make_raw_line("ssh", "decky-01", "connection", "10.0.0.1", _TS1)
        row = _make_log_row(raw_line=raw, attacker_ip="10.0.0.1")
        repo = _make_repo(logs=[row])
        await _rebuild(repo)
        repo.upsert_attacker.assert_awaited_once()
        record = repo.upsert_attacker.call_args[0][0]
        assert record["ip"] == "10.0.0.1"
        assert record["event_count"] == 1

    @pytest.mark.asyncio
    async def test_multiple_attackers_all_upserted(self):
        rows = [
            _make_log_row(
                raw_line=_make_raw_line("ssh", "decky-01", "conn", ip, _TS1),
                attacker_ip=ip,
            )
            for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        ]
        repo = _make_repo(logs=rows)
        await _rebuild(repo)
        assert repo.upsert_attacker.await_count == 3
        upserted_ips = {c[0][0]["ip"] for c in repo.upsert_attacker.call_args_list}
        assert upserted_ips == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}

    @pytest.mark.asyncio
    async def test_traversal_detected_across_two_deckies(self):
        rows = [
            _make_log_row(
                raw_line=_make_raw_line("ssh", "decky-01", "conn", "5.5.5.5", _TS1),
                attacker_ip="5.5.5.5", decky="decky-01",
            ),
            _make_log_row(
                raw_line=_make_raw_line("http", "decky-02", "req", "5.5.5.5", _TS2),
                attacker_ip="5.5.5.5", decky="decky-02",
            ),
        ]
        repo = _make_repo(logs=rows)
        await _rebuild(repo)
        record = repo.upsert_attacker.call_args[0][0]
        assert record["is_traversal"] is True
        assert "decky-01" in record["traversal_path"]
        assert "decky-02" in record["traversal_path"]

    @pytest.mark.asyncio
    async def test_single_decky_not_traversal(self):
        rows = [
            _make_log_row(
                raw_line=_make_raw_line("ssh", "decky-01", "conn", "7.7.7.7", _TS1),
                attacker_ip="7.7.7.7",
            ),
            _make_log_row(
                raw_line=_make_raw_line("http", "decky-01", "req", "7.7.7.7", _TS2),
                attacker_ip="7.7.7.7",
            ),
        ]
        repo = _make_repo(logs=rows)
        await _rebuild(repo)
        record = repo.upsert_attacker.call_args[0][0]
        assert record["is_traversal"] is False

    @pytest.mark.asyncio
    async def test_bounties_merged_into_record(self):
        raw = _make_raw_line("ssh", "decky-01", "conn", "8.8.8.8", _TS1)
        repo = _make_repo(
            logs=[_make_log_row(raw_line=raw, attacker_ip="8.8.8.8")],
            bounties={"8.8.8.8": [
                {"bounty_type": "credential", "attacker_ip": "8.8.8.8", "payload": {}},
                {"bounty_type": "fingerprint", "attacker_ip": "8.8.8.8", "payload": {"ja3": "abc"}},
            ]},
        )
        await _rebuild(repo)
        record = repo.upsert_attacker.call_args[0][0]
        assert record["bounty_count"] == 2
        assert record["credential_count"] == 1
        fps = json.loads(record["fingerprints"])
        assert len(fps) == 1

    @pytest.mark.asyncio
    async def test_commands_extracted_during_rebuild(self):
        raw = _make_raw_line("ssh", "decky-01", "command", "9.9.9.9", _TS1)
        row = _make_log_row(
            raw_line=raw,
            attacker_ip="9.9.9.9",
            event_type="command",
            fields=json.dumps({"command": "cat /etc/passwd"}),
        )
        repo = _make_repo(logs=[row])
        await _rebuild(repo)
        record = repo.upsert_attacker.call_args[0][0]
        commands = json.loads(record["commands"])
        assert len(commands) == 1
        assert commands[0]["command"] == "cat /etc/passwd"


# ─── attacker_profile_worker ──────────────────────────────────────────────────

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
    async def test_worker_handles_rebuild_error_without_crashing(self):
        repo = _make_repo()
        _call_count = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        async def bad_rebuild(_repo):
            raise RuntimeError("DB exploded")

        with patch("decnet.web.attacker_worker.asyncio.sleep", side_effect=fake_sleep):
            with patch("decnet.web.attacker_worker._rebuild", side_effect=bad_rebuild):
                with pytest.raises(asyncio.CancelledError):
                    await attacker_profile_worker(repo)

    @pytest.mark.asyncio
    async def test_worker_calls_rebuild_after_sleep(self):
        repo = _make_repo()
        _call_count = 0

        async def fake_sleep(secs):
            nonlocal _call_count
            _call_count += 1
            if _call_count >= 2:
                raise asyncio.CancelledError()

        rebuild_calls = []

        async def mock_rebuild(_repo):
            rebuild_calls.append(True)

        with patch("decnet.web.attacker_worker.asyncio.sleep", side_effect=fake_sleep):
            with patch("decnet.web.attacker_worker._rebuild", side_effect=mock_rebuild):
                with pytest.raises(asyncio.CancelledError):
                    await attacker_profile_worker(repo)

        assert len(rebuild_calls) >= 1


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
