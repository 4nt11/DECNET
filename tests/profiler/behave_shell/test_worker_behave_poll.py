# SPDX-License-Identifier: AGPL-3.0-or-later
"""W.3 poll-fallback tests.

Exercises ``_behave_poll_tick`` and ``_payload_from_log_row`` —
the path used when the bus is unavailable
(``DECNET_BUS_ENABLED=false`` or transient subscriber failure).
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

from decnet.profiler.worker import (
    _behave_poll_tick,
    _BEHAVE_POLL_STATE_KEY,
    _payload_from_log_row,
)


def _log_row(
    log_id: int = 42,
    event_type: str = "session_recorded",
    fields: dict | None = None,
) -> dict[str, Any]:
    base_fields = {"sid": "11111111-2222-3333-4444-555555555555",
                   "service": "ssh", "duration_s": "5.0",
                   "src_ip": "10.0.0.5"}
    if fields is not None:
        base_fields.update(fields)
    return {
        "id": log_id,
        "event_type": event_type,
        "decky": "test-decky",
        "service": "ssh",
        "attacker_ip": "10.0.0.5",
        "timestamp": "2026-05-08T10:00:00",
        "fields": json.dumps(base_fields),
    }


def test_payload_from_log_row_happy() -> None:
    payload = _payload_from_log_row(_log_row())
    assert payload is not None
    assert payload["session_id"] == "11111111-2222-3333-4444-555555555555"
    assert payload["decky_id"] == "test-decky"
    assert payload["service"] == "ssh"
    assert payload["attacker_ip"] == "10.0.0.5"
    # shard_path may be None (no fixture file) — that's the honest
    # "skip until next tick" path.
    assert "shard_path" in payload


def test_payload_from_log_row_returns_none_on_missing_fields() -> None:
    """Empty fields blob → required-field guard short-circuits."""
    row = _log_row(fields={"sid": ""})
    row["fields"] = "{}"
    assert _payload_from_log_row(row) is None


def test_payload_from_log_row_returns_none_on_unparseable_fields() -> None:
    row = _log_row()
    row["fields"] = "not json"
    assert _payload_from_log_row(row) is None


async def test_poll_tick_no_logs_does_nothing() -> None:
    repo = AsyncMock()
    repo.get_state = AsyncMock(return_value=None)
    repo.get_logs_after_id = AsyncMock(return_value=[])

    await _behave_poll_tick(repo, None)

    repo.get_logs_after_id.assert_awaited_once()
    repo.set_state.assert_not_awaited()


async def test_poll_tick_skips_non_session_recorded_event_types() -> None:
    repo = AsyncMock()
    repo.get_state = AsyncMock(return_value=None)
    repo.get_logs_after_id = AsyncMock(return_value=[
        _log_row(log_id=1, event_type="command"),
        _log_row(log_id=2, event_type="connection.opened"),
    ])

    await _behave_poll_tick(repo, None)

    # Cursor still advances even when nothing is processed.
    repo.set_state.assert_awaited_once_with(
        _BEHAVE_POLL_STATE_KEY, {"last_log_id": 2},
    )
    repo.has_observations_for_evidence.assert_not_awaited()


async def test_poll_tick_drives_handler_for_session_recorded(monkeypatch) -> None:
    captured: list[dict[str, Any]] = []

    async def _fake_handler(repo, payload, publish):
        captured.append(payload)
        return 0

    monkeypatch.setattr(
        "decnet.profiler.worker.handle_session_ended", _fake_handler,
    )

    repo = AsyncMock()
    repo.get_state = AsyncMock(return_value={"last_log_id": 0})
    repo.get_logs_after_id = AsyncMock(return_value=[_log_row(log_id=99)])

    await _behave_poll_tick(repo, None)

    assert len(captured) == 1
    assert captured[0]["session_id"] == "11111111-2222-3333-4444-555555555555"
    repo.set_state.assert_awaited_once_with(
        _BEHAVE_POLL_STATE_KEY, {"last_log_id": 99},
    )


async def test_poll_tick_uses_separate_cursor_state_key(monkeypatch) -> None:
    """Cursor key must be _BEHAVE_POLL_STATE_KEY, NOT
    attacker_worker_cursor (which the correlation tick owns)."""
    repo = AsyncMock()
    repo.get_state = AsyncMock(return_value=None)
    repo.get_logs_after_id = AsyncMock(return_value=[_log_row(log_id=5)])

    async def _noop(*_a, **_k):
        return 0

    monkeypatch.setattr(
        "decnet.profiler.worker.handle_session_ended", _noop,
    )

    await _behave_poll_tick(repo, None)

    # Read uses the separate key.
    repo.get_state.assert_awaited_with(_BEHAVE_POLL_STATE_KEY)
    # Write also uses it.
    repo.set_state.assert_awaited_with(
        _BEHAVE_POLL_STATE_KEY, {"last_log_id": 5},
    )


async def test_poll_tick_isolates_handler_exception(monkeypatch) -> None:
    """A blowing-up handler must not stop cursor advancement on
    subsequent rows."""
    call_count = 0

    async def _maybe_blowing_handler(repo, payload, publish):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("handler exploded")
        return 0

    monkeypatch.setattr(
        "decnet.profiler.worker.handle_session_ended",
        _maybe_blowing_handler,
    )

    repo = AsyncMock()
    repo.get_state = AsyncMock(return_value=None)
    repo.get_logs_after_id = AsyncMock(return_value=[
        _log_row(log_id=1),
        _log_row(log_id=2),
    ])

    # Should not raise.
    await _behave_poll_tick(repo, None)
    assert call_count == 2
    # Cursor advanced past both rows.
    repo.set_state.assert_awaited_once_with(
        _BEHAVE_POLL_STATE_KEY, {"last_log_id": 2},
    )
