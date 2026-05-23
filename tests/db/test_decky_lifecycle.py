# SPDX-License-Identifier: AGPL-3.0-or-later
"""DeckyLifecycle repo CRUD + sweep tests.

State machine: pending → running → succeeded | failed.  Rows are
append-only after terminal; retries write a new row.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path: Path):
    r = get_repository(db_path=str(tmp_path / "lifecycle.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_create_lifecycle_returns_id_and_defaults_pending(repo) -> None:
    lid = await repo.create_lifecycle(
        {"decky_name": "decky-01", "operation": "deploy"},
    )
    assert isinstance(lid, str) and lid
    rows = await repo.get_lifecycle_by_ids([lid])
    assert len(rows) == 1
    row = rows[0]
    assert row["decky_name"] == "decky-01"
    assert row["operation"] == "deploy"
    assert row["status"] == "pending"
    assert row["error"] is None
    assert row["completed_at"] is None
    assert row["started_at"] is not None
    assert row["updated_at"] is not None


@pytest.mark.anyio
async def test_update_lifecycle_terminal_stamps_completed_at(repo) -> None:
    lid = await repo.create_lifecycle(
        {"decky_name": "decky-01", "operation": "mutate"},
    )
    await repo.update_lifecycle(lid, {"status": "running"})
    rows = await repo.get_lifecycle_by_ids([lid])
    assert rows[0]["status"] == "running"
    assert rows[0]["completed_at"] is None

    await repo.update_lifecycle(
        lid, {"status": "succeeded"},
    )
    rows = await repo.get_lifecycle_by_ids([lid])
    assert rows[0]["status"] == "succeeded"
    assert rows[0]["completed_at"] is not None


@pytest.mark.anyio
async def test_update_lifecycle_failure_carries_error(repo) -> None:
    lid = await repo.create_lifecycle(
        {"decky_name": "decky-01", "operation": "deploy"},
    )
    await repo.update_lifecycle(
        lid, {"status": "failed", "error": "compose blew up"},
    )
    rows = await repo.get_lifecycle_by_ids([lid])
    assert rows[0]["status"] == "failed"
    assert rows[0]["error"] == "compose blew up"
    assert rows[0]["completed_at"] is not None


@pytest.mark.anyio
async def test_get_lifecycle_by_ids_empty_list_returns_empty(repo) -> None:
    assert await repo.get_lifecycle_by_ids([]) == []


@pytest.mark.anyio
async def test_get_lifecycle_by_ids_unknown_id_silently_omitted(repo) -> None:
    lid = await repo.create_lifecycle(
        {"decky_name": "d", "operation": "deploy"},
    )
    rows = await repo.get_lifecycle_by_ids([lid, "no-such-id"])
    assert len(rows) == 1
    assert rows[0]["id"] == lid


@pytest.mark.anyio
async def test_find_open_lifecycle_matches_pending_and_running(repo) -> None:
    p = await repo.create_lifecycle(
        {"decky_name": "decky-01", "operation": "deploy"},
    )
    found = await repo.find_open_lifecycle("decky-01", "deploy")
    assert found is not None
    assert found["id"] == p

    await repo.update_lifecycle(p, {"status": "running"})
    found = await repo.find_open_lifecycle("decky-01", "deploy")
    assert found is not None
    assert found["status"] == "running"


@pytest.mark.anyio
async def test_find_open_lifecycle_skips_terminal_rows(repo) -> None:
    lid = await repo.create_lifecycle(
        {"decky_name": "decky-01", "operation": "deploy"},
    )
    await repo.update_lifecycle(lid, {"status": "succeeded"})
    assert await repo.find_open_lifecycle("decky-01", "deploy") is None


@pytest.mark.anyio
async def test_find_open_lifecycle_host_uuid_filter(repo) -> None:
    a = await repo.create_lifecycle(
        {"decky_name": "d", "operation": "deploy", "host_uuid": "h1"},
    )
    await repo.create_lifecycle(
        {"decky_name": "d", "operation": "deploy", "host_uuid": "h2"},
    )
    found = await repo.find_open_lifecycle("d", "deploy", host_uuid="h1")
    assert found is not None
    assert found["id"] == a


@pytest.mark.anyio
async def test_sweep_marks_stale_rows_failed(repo) -> None:
    # Stale: started_at well in the past, still pending.
    stale_id = await repo.create_lifecycle(
        {"decky_name": "old", "operation": "deploy"},
    )
    # Force its started_at backwards via update (sweep relies on it).
    long_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    await repo.update_lifecycle(stale_id, {"started_at": long_ago})

    # Fresh: just-created, must NOT be swept.
    fresh_id = await repo.create_lifecycle(
        {"decky_name": "new", "operation": "deploy"},
    )

    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    swept = await repo.sweep_stale_lifecycle(
        cutoff, reason="master restarted during operation",
    )
    assert swept == 1

    rows = await repo.get_lifecycle_by_ids([stale_id, fresh_id])
    by_id = {r["id"]: r for r in rows}
    assert by_id[stale_id]["status"] == "failed"
    assert by_id[stale_id]["error"] == "master restarted during operation"
    assert by_id[stale_id]["completed_at"] is not None
    assert by_id[fresh_id]["status"] == "pending"


@pytest.mark.anyio
async def test_sweep_no_op_when_no_stale_rows(repo) -> None:
    await repo.create_lifecycle({"decky_name": "d", "operation": "deploy"})
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    assert await repo.sweep_stale_lifecycle(cutoff, reason="x") == 0
