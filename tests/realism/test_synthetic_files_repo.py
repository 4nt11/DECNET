"""record / update / list / pick-for-edit on the synthetic_files table.

Stage 3 of the realism migration introduces the synthetic_files
table for per-(decky, path) state.  Tests pin the contract on a
real :class:`SQLiteRepository` so SQLModel schema bugs surface here
rather than in production.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from decnet.web.db.sqlite.repository import SQLiteRepository


@pytest_asyncio.fixture
async def repo(tmp_path):
    r = SQLiteRepository(db_path=str(tmp_path / "decnet.db"))
    await r.initialize()
    yield r
    await r.engine.dispose()


def _row(
    decky: str = "d1",
    path: str = "/home/admin/TODO.md",
    persona: str = "admin",
    cls: str = "todo",
    body: str = "- [ ] rotate keys\n",
    ts: datetime | None = None,
) -> dict:
    now = ts or datetime.now(timezone.utc)
    return {
        "decky_uuid": decky,
        "path": path,
        "persona": persona,
        "content_class": cls,
        "created_at": now,
        "last_modified": now,
        "edit_count": 0,
        "content_hash": hashlib.sha256(body.encode()).hexdigest(),
        "last_body": body,
    }


@pytest.mark.asyncio
async def test_record_returns_uuid(repo):
    uuid = await repo.record_synthetic_file(_row())
    assert isinstance(uuid, str) and uuid


@pytest.mark.asyncio
async def test_unique_constraint_on_decky_path(repo):
    await repo.record_synthetic_file(_row())
    with pytest.raises(Exception):
        await repo.record_synthetic_file(_row())


@pytest.mark.asyncio
async def test_update_synthetic_file_patches_fields(repo):
    uuid = await repo.record_synthetic_file(_row())
    await repo.update_synthetic_file(
        uuid,
        {"edit_count": 1, "last_body": "- [x] rotate keys\n"},
    )
    listing = await repo.list_synthetic_files(decky_uuid="d1")
    assert len(listing) == 1
    assert listing[0]["edit_count"] == 1
    assert listing[0]["last_body"].startswith("- [x]")


@pytest.mark.asyncio
async def test_list_filters_by_decky_and_persona(repo):
    await repo.record_synthetic_file(_row(decky="d1", path="/a"))
    await repo.record_synthetic_file(_row(decky="d1", path="/b", persona="ubuntu"))
    await repo.record_synthetic_file(_row(decky="d2", path="/c"))

    by_decky = await repo.list_synthetic_files(decky_uuid="d1")
    assert {r["path"] for r in by_decky} == {"/a", "/b"}

    by_persona = await repo.list_synthetic_files(decky_uuid="d1", persona="ubuntu")
    assert {r["path"] for r in by_persona} == {"/b"}


@pytest.mark.asyncio
async def test_pick_random_returns_none_when_empty(repo):
    assert await repo.pick_random_synthetic_file_for_edit("d-empty") is None


@pytest.mark.asyncio
async def test_pick_random_excludes_canary_classes(repo):
    # Canary-class files are stored on the same table (stage 7) but
    # the editor must skip them — their bodies are binary blobs.
    await repo.record_synthetic_file(_row(cls="canary_aws_creds"))
    picked = await repo.pick_random_synthetic_file_for_edit("d1")
    assert picked is None


@pytest.mark.asyncio
async def test_pick_random_excludes_too_old_rows(repo):
    old = datetime.now(timezone.utc) - timedelta(days=120)
    await repo.record_synthetic_file(_row(ts=old))
    picked = await repo.pick_random_synthetic_file_for_edit("d1", max_age_days=30)
    assert picked is None


@pytest.mark.asyncio
async def test_pick_random_returns_eligible_row(repo):
    await repo.record_synthetic_file(_row(cls="todo"))
    picked = await repo.pick_random_synthetic_file_for_edit("d1")
    assert picked is not None
    assert picked["content_class"] == "todo"
    assert picked["path"] == "/home/admin/TODO.md"


@pytest.mark.asyncio
async def test_count_synthetic_files_respects_filters(repo):
    await repo.record_synthetic_file(_row(decky="d1", path="/a", cls="todo"))
    await repo.record_synthetic_file(_row(decky="d1", path="/b", cls="note"))
    await repo.record_synthetic_file(_row(decky="d2", path="/c", cls="todo"))
    assert await repo.count_synthetic_files() == 3
    assert await repo.count_synthetic_files(decky_uuid="d1") == 2
    assert await repo.count_synthetic_files(content_class="todo") == 2
    assert await repo.count_synthetic_files(
        decky_uuid="d1", content_class="note",
    ) == 1


@pytest.mark.asyncio
async def test_list_filters_by_content_class(repo):
    await repo.record_synthetic_file(_row(decky="d1", path="/a", cls="todo"))
    await repo.record_synthetic_file(_row(decky="d1", path="/b", cls="note"))
    rows = await repo.list_synthetic_files(content_class="todo")
    assert len(rows) == 1
    assert rows[0]["content_class"] == "todo"


@pytest.mark.asyncio
async def test_get_synthetic_file_returns_row(repo):
    uuid = await repo.record_synthetic_file(_row(decky="d1", path="/a"))
    got = await repo.get_synthetic_file(uuid)
    assert got is not None
    assert got["uuid"] == uuid
    assert got["path"] == "/a"


@pytest.mark.asyncio
async def test_get_synthetic_file_returns_none_when_missing(repo):
    assert await repo.get_synthetic_file("does-not-exist") is None
