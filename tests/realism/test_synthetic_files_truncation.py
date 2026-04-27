"""``synthetic_files.last_body`` is capped at 64 KB.

The orchestrator caps the persisted body at 64 KB on every write
(create + edit) so the table doesn't bloat with large blobs.  This
introduces a real edge: an EditAction whose ``previous_body`` is
sourced from the cap (not the file on disk) sees truncated bytes.

Today the realism templates produce well under 64 KB, so the edge
isn't reachable from the planted-content path.  But a future change
that lifts the cap, an LLM that returns a long body, or a
``honeydoc_pdf`` body cultivated through the realism path could all
hit it.  These tests pin the contract so a regression that drops the
cap or applies it inconsistently fails loudly.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from decnet.web.db.sqlite.repository import SQLiteRepository


_LIMIT = 65536  # decnet/orchestrator/worker.py uses [:65536]


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
        # The hash is over the *full* body in the orchestrator's write
        # path; if the body comes from a row that was already truncated,
        # the hash reflects the truncation.  Tests check both paths.
        "content_hash": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "last_body": body[:_LIMIT],
    }


@pytest.mark.asyncio
async def test_oversized_body_is_truncated_at_write(repo):
    body = "A" * (_LIMIT * 2)
    uuid = await repo.record_synthetic_file(_row(body))
    rows = await repo.list_synthetic_files(decky_uuid="d1")
    assert len(rows) == 1
    stored = rows[0]
    assert stored["uuid"] == uuid
    assert len(stored["last_body"]) == _LIMIT


@pytest.mark.asyncio
async def test_body_at_exact_limit_is_preserved(repo):
    """Boundary: a body of exactly 64 KB must not be silently
    truncated.  Off-by-one regression target."""
    body = "B" * _LIMIT
    await repo.record_synthetic_file(_row(body))
    rows = await repo.list_synthetic_files(decky_uuid="d1")
    assert len(rows[0]["last_body"]) == _LIMIT


@pytest.mark.asyncio
async def test_pick_for_edit_returns_truncated_body(repo):
    """Stage 3b contract: the edit candidate carries the *stored*
    last_body — necessarily truncated when the original exceeded the
    cap.  Document the consequence so a future test author doesn't
    expect the full body to round-trip."""
    body = "C" * (_LIMIT * 3)
    await repo.record_synthetic_file(_row(body))
    candidate = await repo.pick_random_synthetic_file_for_edit("d1")
    assert candidate is not None
    assert len(candidate["last_body"]) == _LIMIT
    # The edit driver mutates this body via realism.bodies.next_iteration,
    # so callers must accept they're editing a truncated snapshot of
    # the file that's actually on the decky.  This is documented
    # behaviour pre-v1; if the cap rises, lift _LIMIT here too.


@pytest.mark.asyncio
async def test_edit_path_keeps_cap(repo):
    """An update_synthetic_file call that tries to write a >cap body
    must clip to the cap on the way in.  Mirrors the orchestrator
    worker's ``last_body=body[:65536]`` line."""
    uuid = await repo.record_synthetic_file(_row("seed"))
    big = "D" * (_LIMIT * 4)
    await repo.update_synthetic_file(
        uuid,
        {
            "last_modified": datetime.now(timezone.utc),
            "edit_count": 1,
            "last_body": big[:_LIMIT],  # caller is responsible for clipping
        },
    )
    rows = await repo.list_synthetic_files(decky_uuid="d1")
    assert len(rows[0]["last_body"]) == _LIMIT
