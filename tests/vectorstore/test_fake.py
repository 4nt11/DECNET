# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for :class:`FakeVectorStore` and :class:`NullVectorStore`.

The fake is the reference implementation of the BaseVectorStore
contract — every behavior assertion here doubles as a contract test
that any future backend must satisfy.
"""
from __future__ import annotations

import pytest

from decnet.vectorstore.fake import FakeVectorStore, NullVectorStore


@pytest.mark.anyio
async def test_fake_round_trip() -> None:
    s = FakeVectorStore()
    await s.initialize()
    await s.insert("ja3", "sess-1", [1.0, 0.0, 0.0])
    await s.insert("ja3", "sess-2", [0.9, 0.1, 0.0])
    await s.insert("ja3", "sess-3", [0.0, 1.0, 0.0])

    rec = await s.get("ja3", "sess-1")
    assert rec is not None
    assert rec.kind == "ja3"
    assert rec.id == "sess-1"
    assert rec.dim == 3
    assert tuple(rec.vector) == (1.0, 0.0, 0.0)


@pytest.mark.anyio
async def test_fake_knn_orders_by_distance() -> None:
    s = FakeVectorStore()
    await s.initialize()
    await s.insert("ja3", "near", [1.0, 0.0])
    await s.insert("ja3", "far", [0.0, 1.0])
    await s.insert("ja3", "exact", [0.99, 0.01])

    n = await s.knn("ja3", [1.0, 0.0], k=3)
    assert [x.id for x in n] == ["near", "exact", "far"]
    assert n[0].distance == 0.0
    assert n[2].distance > n[1].distance


@pytest.mark.anyio
async def test_fake_knn_unknown_kind_returns_empty() -> None:
    s = FakeVectorStore()
    await s.initialize()
    assert await s.knn("never_seen", [0.1, 0.2]) == []


@pytest.mark.anyio
async def test_fake_dim_mismatch_raises() -> None:
    s = FakeVectorStore()
    await s.initialize()
    await s.insert("hassh", "a", [1.0, 2.0, 3.0])
    with pytest.raises(ValueError, match="dim mismatch"):
        await s.insert("hassh", "b", [1.0, 2.0])


@pytest.mark.anyio
async def test_fake_knn_query_dim_mismatch_raises() -> None:
    s = FakeVectorStore()
    await s.initialize()
    await s.insert("kd", "a", [0.1, 0.2, 0.3])
    with pytest.raises(ValueError):
        await s.knn("kd", [0.1, 0.2])


@pytest.mark.anyio
async def test_fake_replace_existing_id() -> None:
    s = FakeVectorStore()
    await s.initialize()
    await s.insert("k", "id1", [1.0, 0.0])
    await s.insert("k", "id1", [0.0, 1.0])
    rec = await s.get("k", "id1")
    assert tuple(rec.vector) == (0.0, 1.0)


@pytest.mark.anyio
async def test_fake_delete() -> None:
    s = FakeVectorStore()
    await s.initialize()
    await s.insert("k", "id1", [1.0])
    assert await s.delete("k", "id1") is True
    assert await s.delete("k", "id1") is False
    assert await s.get("k", "id1") is None


@pytest.mark.anyio
async def test_fake_health_reports_counts() -> None:
    s = FakeVectorStore()
    await s.initialize()
    h = await s.health()
    assert h == {"ok": True, "backend": "fake", "kinds": 0, "vectors": 0}
    await s.insert("a", "1", [1.0])
    await s.insert("a", "2", [2.0])
    await s.insert("b", "1", [3.0, 4.0])
    h = await s.health()
    assert h["kinds"] == 2
    assert h["vectors"] == 3


@pytest.mark.anyio
async def test_null_store_is_inert() -> None:
    s = NullVectorStore()
    await s.initialize()
    await s.insert("k", "id", [1.0, 2.0])  # no-op
    assert await s.get("k", "id") is None
    assert await s.knn("k", [1.0, 2.0]) == []
    assert await s.delete("k", "id") is False
    h = await s.health()
    assert h["backend"] == "null"
    await s.close()
