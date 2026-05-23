# SPDX-License-Identifier: AGPL-3.0-or-later
"""Repository CRUD coverage for canary blobs / tokens / triggers.

Same harness as the rest of :mod:`tests.db` — spin up a SQLite-backed
:class:`SQLiteRepository` against a tempfile, exercise the public
methods, assert observable state.

We deliberately don't go through the API; that gets its own test
module once the router lands. This file proves the repository layer
in isolation: dedup, refcount-aware delete, slug lookup, atomic
trigger record + counter bump, attribution.
"""
from __future__ import annotations

import hashlib
from typing import AsyncIterator

import pytest
import pytest_asyncio

from decnet.web.db.sqlite.repository import SQLiteRepository
import decnet.web.db.models  # noqa: F401  — registers tables on import


@pytest_asyncio.fixture
async def repo(tmp_path) -> AsyncIterator[SQLiteRepository]:
    r = SQLiteRepository(str(tmp_path / "canary.db"))
    await r.initialize()
    yield r


async def _make_blob(repo: SQLiteRepository, content: bytes, *, by: str = "u1") -> dict:
    return await repo.upsert_canary_blob({
        "sha256": hashlib.sha256(content).hexdigest(),
        "filename": "report.docx",
        "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "size_bytes": len(content),
        "uploaded_by": by,
    })


@pytest.mark.asyncio
async def test_upsert_blob_dedupes_by_sha256(repo: SQLiteRepository) -> None:
    a = await _make_blob(repo, b"same bytes", by="u1")
    b = await _make_blob(repo, b"same bytes", by="u2")
    assert a["uuid"] == b["uuid"], "second upload must return the canonical row"
    # Different bytes → different blob.
    c = await _make_blob(repo, b"different bytes", by="u1")
    assert c["uuid"] != a["uuid"]


@pytest.mark.asyncio
async def test_upsert_blob_requires_sha256(repo: SQLiteRepository) -> None:
    with pytest.raises(ValueError):
        await repo.upsert_canary_blob({"filename": "x", "content_type": "x", "size_bytes": 0, "uploaded_by": "u"})


@pytest.mark.asyncio
async def test_get_blob_by_sha256(repo: SQLiteRepository) -> None:
    blob = await _make_blob(repo, b"x")
    found = await repo.get_canary_blob_by_sha256(blob["sha256"])
    assert found is not None and found["uuid"] == blob["uuid"]
    assert await repo.get_canary_blob_by_sha256("0" * 64) is None


@pytest.mark.asyncio
async def test_list_blobs_carries_token_count(repo: SQLiteRepository) -> None:
    blob = await _make_blob(repo, b"x")
    listed = await repo.list_canary_blobs()
    assert len(listed) == 1 and listed[0]["token_count"] == 0
    await repo.create_canary_token({
        "kind": "http", "decky_name": "web1", "blob_uuid": blob["uuid"],
        "instrumenter": "docx", "placement_path": "/tmp/x.docx",
        "callback_token": "slug-1", "secret_seed": "s", "created_by": "u1",
    })
    listed = await repo.list_canary_blobs()
    assert listed[0]["token_count"] == 1


@pytest.mark.asyncio
async def test_delete_blob_refuses_while_referenced(repo: SQLiteRepository) -> None:
    blob = await _make_blob(repo, b"x")
    await repo.create_canary_token({
        "kind": "http", "decky_name": "web1", "blob_uuid": blob["uuid"],
        "instrumenter": "docx", "placement_path": "/tmp/x.docx",
        "callback_token": "slug-r", "secret_seed": "s", "created_by": "u1",
    })
    assert await repo.delete_canary_blob(blob["uuid"]) is False
    # Even after revoke, the row still references the blob — operator
    # must explicitly clean tokens before they can prune the blob.
    tok = await repo.get_canary_token_by_slug("slug-r")
    await repo.update_canary_token_state(tok["uuid"], "revoked")
    assert await repo.delete_canary_blob(blob["uuid"]) is False


@pytest.mark.asyncio
async def test_delete_blob_returns_false_for_missing(repo: SQLiteRepository) -> None:
    assert await repo.delete_canary_blob("00000000-0000-0000-0000-000000000000") is False


@pytest.mark.asyncio
async def test_token_slug_lookup(repo: SQLiteRepository) -> None:
    await repo.create_canary_token({
        "kind": "http", "decky_name": "web1", "generator": "aws_creds",
        "placement_path": "/home/admin/.aws/credentials",
        "callback_token": "slug-aws", "secret_seed": "s", "created_by": "u1",
    })
    found = await repo.get_canary_token_by_slug("slug-aws")
    assert found is not None and found["decky_name"] == "web1"
    assert await repo.get_canary_token_by_slug("nonexistent") is None


@pytest.mark.asyncio
async def test_list_tokens_filters(repo: SQLiteRepository) -> None:
    await repo.create_canary_token({
        "kind": "http", "decky_name": "web1", "generator": "aws_creds",
        "placement_path": "/a", "callback_token": "s1",
        "secret_seed": "s", "created_by": "u1",
    })
    await repo.create_canary_token({
        "kind": "dns", "decky_name": "web2", "generator": "aws_creds",
        "placement_path": "/b", "callback_token": "s2",
        "secret_seed": "s", "created_by": "u1",
    })
    assert len(await repo.list_canary_tokens()) == 2
    assert len(await repo.list_canary_tokens(decky_name="web1")) == 1
    assert len(await repo.list_canary_tokens(kind="dns")) == 1
    assert len(await repo.list_canary_tokens(state="revoked")) == 0


@pytest.mark.asyncio
async def test_record_trigger_bumps_counters_atomically(repo: SQLiteRepository) -> None:
    await repo.create_canary_token({
        "kind": "http", "decky_name": "web1", "generator": "aws_creds",
        "placement_path": "/a", "callback_token": "slug-c",
        "secret_seed": "s", "created_by": "u1",
    })
    tok = await repo.get_canary_token_by_slug("slug-c")
    assert tok["trigger_count"] == 0 and tok["last_triggered_at"] is None
    trig_id = await repo.record_canary_trigger({
        "token_uuid": tok["uuid"], "src_ip": "1.2.3.4",
        "request_path": "/c/slug-c", "user_agent": "curl/8.0",
        "raw_headers": {"user-agent": "curl/8.0"},
    })
    assert trig_id
    tok2 = await repo.get_canary_token_by_slug("slug-c")
    assert tok2["trigger_count"] == 1
    assert tok2["last_triggered_at"] is not None
    # raw_headers stored as JSON text and decodes via the model helper.
    triggers = await repo.list_canary_triggers(tok["uuid"])
    assert len(triggers) == 1
    assert triggers[0]["src_ip"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_attribute_trigger_sets_attacker(repo: SQLiteRepository) -> None:
    await repo.create_canary_token({
        "kind": "http", "decky_name": "web1", "generator": "aws_creds",
        "placement_path": "/a", "callback_token": "slug-at",
        "secret_seed": "s", "created_by": "u1",
    })
    tok = await repo.get_canary_token_by_slug("slug-at")
    trig_id = await repo.record_canary_trigger({
        "token_uuid": tok["uuid"], "src_ip": "9.9.9.9",
    })
    assert await repo.attribute_canary_trigger(trig_id, "attacker-uuid-123") is True
    assert await repo.attribute_canary_trigger("missing-trig", "x") is False
    triggers = await repo.list_canary_triggers(tok["uuid"])
    assert triggers[0]["attacker_id"] == "attacker-uuid-123"


@pytest.mark.asyncio
async def test_get_token_returns_none_for_missing(repo: SQLiteRepository) -> None:
    assert await repo.get_canary_token("00000000-0000-0000-0000-000000000000") is None
    assert await repo.get_canary_blob("00000000-0000-0000-0000-000000000000") is None


@pytest.mark.asyncio
async def test_update_state_returns_false_for_missing(repo: SQLiteRepository) -> None:
    assert await repo.update_canary_token_state("missing", "revoked") is False
