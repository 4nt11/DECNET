"""Pagination + filter + prune for orchestrator_events repo methods."""
from __future__ import annotations

import json

import pytest

from decnet.web.db.models import Topology, TopologyDecky
from decnet.web.db.sqlite.repository import SQLiteRepository


async def _make_repo(tmp_path, name: str) -> SQLiteRepository:
    r = SQLiteRepository(db_path=str(tmp_path / name))
    await r.initialize()
    return r


@pytest.mark.asyncio
async def test_empty_table_zero_total(tmp_path):
    repo = await _make_repo(tmp_path, "orch.db")
    assert await repo.list_orchestrator_events(limit=50, offset=0) == []
    assert await repo.count_orchestrator_events() == 0


async def _seed_decky(repo: SQLiteRepository, name: str = "d-1") -> str:
    async with repo._session() as session:
        topo = Topology(name=f"t-{name}", config_snapshot="{}", status="active")
        session.add(topo)
        await session.commit()
        await session.refresh(topo)
        d = TopologyDecky(
            topology_id=topo.id, name=name,
            services=json.dumps(["ssh"]), ip="10.0.0.2", state="running",
        )
        session.add(d)
        await session.commit()
        await session.refresh(d)
        return d.uuid


async def _seed(
    repo: SQLiteRepository,
    n: int = 5,
    kind: str = "traffic",
    dst: str | None = None,
) -> str:
    if dst is None:
        dst = await _seed_decky(repo, "decky-A")
    for i in range(n):
        await repo.record_orchestrator_event({
            "kind": kind,
            "protocol": "ssh",
            "action": f"exec:{i}",
            "src_decky_uuid": None,
            "dst_decky_uuid": dst,
            "success": True,
            "payload": {"i": i},
        })
    return dst


@pytest.mark.asyncio
async def test_pagination_respects_limit_offset(tmp_path):
    repo = await _make_repo(tmp_path, "p.db")
    await _seed(repo, n=5)

    assert await repo.count_orchestrator_events() == 5
    page1 = await repo.list_orchestrator_events(limit=2, offset=0)
    page2 = await repo.list_orchestrator_events(limit=2, offset=2)
    assert len(page1) == 2
    assert len(page2) == 2
    assert {r["uuid"] for r in page1}.isdisjoint({r["uuid"] for r in page2})


@pytest.mark.asyncio
async def test_kind_filter_narrows(tmp_path):
    repo = await _make_repo(tmp_path, "k.db")
    dst = await _seed_decky(repo, "decky-K")
    for i in range(3):
        await repo.record_orchestrator_event({
            "kind": "traffic", "protocol": "ssh", "action": f"a{i}",
            "src_decky_uuid": None, "dst_decky_uuid": dst,
            "success": True, "payload": {},
        })
    for i in range(2):
        await repo.record_orchestrator_event({
            "kind": "file", "protocol": "ssh", "action": f"f{i}",
            "src_decky_uuid": None, "dst_decky_uuid": dst,
            "success": True, "payload": {},
        })

    assert await repo.count_orchestrator_events() == 5
    assert await repo.count_orchestrator_events(kind="traffic") == 3
    assert await repo.count_orchestrator_events(kind="file") == 2

    only_file = await repo.list_orchestrator_events(limit=50, kind="file")
    assert {r["kind"] for r in only_file} == {"file"}


@pytest.mark.asyncio
async def test_count_failures_window_and_kind(tmp_path):
    """count_orchestrator_failures must:
    - count both tables (events + emails) when kind is None
    - respect the since_ts cutoff
    - skip success=True rows
    - narrow to a single source table when kind is set"""
    from datetime import datetime, timedelta, timezone

    repo = await _make_repo(tmp_path, "failures.db")
    dst = await _seed_decky(repo, "decky-A")

    # 2 fresh failures + 1 fresh success on the events table.
    for i in range(2):
        await repo.record_orchestrator_event({
            "kind": "traffic", "protocol": "ssh",
            "action": f"fail:{i}", "src_decky_uuid": None,
            "dst_decky_uuid": dst, "success": False, "payload": {},
        })
    await repo.record_orchestrator_event({
        "kind": "traffic", "protocol": "ssh",
        "action": "ok", "src_decky_uuid": None,
        "dst_decky_uuid": dst, "success": True, "payload": {},
    })

    # 1 fresh email failure.
    await repo.record_orchestrator_email({
        "ts": datetime.now(timezone.utc),
        "subject": "boom", "sender_email": "a@x", "recipient_email": "b@y",
        "mail_decky_uuid": "mh", "language": "en",
        "thread_id": "t1", "message_id": "<m1@x>", "in_reply_to": None,
        "eml_path": "/tmp/m1.eml",
        "success": False, "payload": "{}",
    })

    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)

    assert await repo.count_orchestrator_failures(since_ts=cutoff) == 3
    assert (
        await repo.count_orchestrator_failures(since_ts=cutoff, kind="traffic")
    ) == 2
    assert (
        await repo.count_orchestrator_failures(since_ts=cutoff, kind="email")
    ) == 1
    # Future cutoff → nothing matches.
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    assert await repo.count_orchestrator_failures(since_ts=future) == 0


@pytest.mark.asyncio
async def test_prune_caps_per_dst(tmp_path):
    repo = await _make_repo(tmp_path, "prune.db")
    await _seed(repo, n=10)

    deleted = await repo.prune_orchestrator_events(per_dst_cap=3)
    assert deleted == 7
    assert await repo.count_orchestrator_events() == 3
