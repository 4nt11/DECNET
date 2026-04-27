"""``synthetic_files.last_body`` is capped at 64 KB by the repo.

The repo clips on both insert and update so callers may pass the full
body. Large blobs (DOCX/PDF, canary artifacts) would bloat the table;
the decky filesystem holds the canonical bytes.

These tests pin the contract so a regression that drops the cap or
applies it inconsistently fails loudly. Note: callers pass the *full*
body — the worker no longer clips; the repo does.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from decnet.web.db.models.realism import SYNTHETIC_FILE_BODY_LIMIT
from decnet.web.db.sqlite.repository import SQLiteRepository


_LIMIT = SYNTHETIC_FILE_BODY_LIMIT


@pytest_asyncio.fixture
async def repo(tmp_path):
    r = SQLiteRepository(db_path=str(tmp_path / "decnet.db"))
    await r.initialize()
    yield r
    await r.engine.dispose()


def _row(body: str) -> dict:
    import hashlib
    now = datetime.now(timezone.utc)
    return {
        "decky_uuid": "d1",
        "path": "/home/admin/notes.txt",
        "persona": "admin",
        "content_class": "note",
        "created_at": now,
        "last_modified": now,
        "edit_count": 0,
        "content_hash": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        # Caller passes the full body — the repo clips.
        "last_body": body,
    }


@pytest.mark.asyncio
async def test_repo_clips_oversized_body_at_insert(repo):
    body = "A" * (_LIMIT * 2)
    uuid = await repo.record_synthetic_file(_row(body))
    rows = await repo.list_synthetic_files(decky_uuid="d1")
    assert len(rows) == 1
    stored = rows[0]
    assert stored["uuid"] == uuid
    assert len(stored["last_body"]) == _LIMIT


@pytest.mark.asyncio
async def test_body_at_exact_limit_is_preserved(repo):
    body = "B" * _LIMIT
    await repo.record_synthetic_file(_row(body))
    rows = await repo.list_synthetic_files(decky_uuid="d1")
    assert len(rows[0]["last_body"]) == _LIMIT


@pytest.mark.asyncio
async def test_pick_for_edit_returns_clipped_body(repo):
    body = "C" * (_LIMIT * 3)
    await repo.record_synthetic_file(_row(body))
    candidate = await repo.pick_random_synthetic_file_for_edit("d1")
    assert candidate is not None
    assert len(candidate["last_body"]) == _LIMIT


@pytest.mark.asyncio
async def test_repo_clips_oversized_body_at_update(repo):
    uuid = await repo.record_synthetic_file(_row("seed"))
    big = "D" * (_LIMIT * 4)
    await repo.update_synthetic_file(
        uuid,
        {
            "last_modified": datetime.now(timezone.utc),
            "edit_count": 1,
            "last_body": big,
        },
    )
    rows = await repo.list_synthetic_files(decky_uuid="d1")
    assert len(rows[0]["last_body"]) == _LIMIT
