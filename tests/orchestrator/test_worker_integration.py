"""End-to-end-ish: run one orchestrator tick against a real SQLite repo +
FakeBus, with the docker subprocess stubbed.  Verifies that:

* :func:`scheduler.pick` reads the deckies the repo returns,
* the driver result is persisted to ``orchestrator_events``,
* a bus event is published to the right topic.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio

from decnet.bus.fake import FakeBus
from decnet.orchestrator import worker as orch_worker
from decnet.orchestrator.drivers import ssh as ssh_driver
from decnet.web.db.models import TopologyDecky, Topology
from decnet.web.db.sqlite.repository import SQLiteRepository


@pytest_asyncio.fixture
async def repo(tmp_path):
    r = SQLiteRepository(db_path=str(tmp_path / "decnet.db"))
    await r.initialize()
    yield r
    await r.engine.dispose()


@pytest_asyncio.fixture
async def fake_bus():
    bus = FakeBus()
    await bus.connect()
    try:
        yield bus
    finally:
        await bus.close()


async def _seed_two_running_ssh_deckies(repo: SQLiteRepository) -> tuple[str, str]:
    async with repo._session() as session:
        topo = Topology(name="t1", config_snapshot="{}", status="active")
        session.add(topo)
        await session.commit()
        await session.refresh(topo)
        d1 = TopologyDecky(
            topology_id=topo.id, name="decky-01",
            services=json.dumps(["ssh"]), ip="10.0.0.1", state="running",
        )
        d2 = TopologyDecky(
            topology_id=topo.id, name="decky-02",
            services=json.dumps(["ssh"]), ip="10.0.0.2", state="running",
        )
        session.add(d1)
        session.add(d2)
        await session.commit()
        await session.refresh(d1)
        await session.refresh(d2)
        return d1.uuid, d2.uuid


@pytest.mark.asyncio
async def test_one_tick_records_event_and_publishes(repo, fake_bus, monkeypatch):
    await _seed_two_running_ssh_deckies(repo)

    # Pretend every docker exec succeeds with an SSH banner; that lets
    # both action kinds (traffic + file) land as success rows so the
    # assertions below don't have to care which one the scheduler picked.
    async def fake_run(argv):
        if argv[3] == "python3":
            return 0, "SSH-2.0-OpenSSH_9.6\r\n", ""
        return 0, "", ""

    monkeypatch.setattr(ssh_driver, "_run", fake_run)

    async def fake_run_with_stdin(argv, stdin_bytes):
        # plant_file takes the base64-streaming path; treat any docker
        # exec write as a successful no-op for the integration test.
        return 0, "", ""

    monkeypatch.setattr(ssh_driver, "_run_with_stdin", fake_run_with_stdin)

    received: list = []

    async def collect():
        async with fake_bus.subscribe("orchestrator.>") as sub:
            async for ev in sub:
                received.append(ev)
                if len(received) >= 1:
                    return

    import asyncio
    collector = asyncio.create_task(collect())
    # Yield once so the subscription is registered before we publish.
    await asyncio.sleep(0)

    await orch_worker._one_tick(repo, fake_bus)

    await asyncio.wait_for(collector, timeout=2.0)

    rows = await repo.list_orchestrator_events(limit=10)
    assert len(rows) == 1
    row = rows[0]
    assert row["success"] is True
    assert row["protocol"] == "ssh"
    assert row["kind"] in {"traffic", "file"}

    assert len(received) == 1
    ev = received[0]
    assert ev.topic.startswith("orchestrator.")
    assert ev.payload["success"] is True
    assert ev.payload["kind"] == row["kind"]


@pytest.mark.asyncio
async def test_one_tick_picks_fleet_deckies(repo, fake_bus, monkeypatch):
    """Regression: orchestrator was permanently blind to unihost MACVLAN /
    IPVLAN deckies because list_running_topology_deckies only scans
    topology_deckies.  The new union view (list_running_deckies) must
    pull in fleet_deckies rows too."""
    await repo.upsert_fleet_decky({
        "host_uuid": "local",
        "name": "fleet-d1",
        "services": ["ssh"],
        "decky_ip": "10.0.0.50",
        "state": "running",
    })
    await repo.upsert_fleet_decky({
        "host_uuid": "local",
        "name": "fleet-d2",
        "services": ["ssh"],
        "decky_ip": "10.0.0.51",
        "state": "running",
    })

    async def fake_run(argv):
        if argv[3] == "python3":
            return 0, "SSH-2.0-OpenSSH_9.6\r\n", ""
        return 0, "", ""

    monkeypatch.setattr(ssh_driver, "_run", fake_run)

    async def fake_run_with_stdin(argv, stdin_bytes):
        # plant_file takes the base64-streaming path; treat any docker
        # exec write as a successful no-op for the integration test.
        return 0, "", ""

    monkeypatch.setattr(ssh_driver, "_run_with_stdin", fake_run_with_stdin)

    await orch_worker._one_tick(repo, fake_bus)

    rows = await repo.list_orchestrator_events(limit=10)
    assert len(rows) == 1
    # The dst_decky_uuid is our composite "host_uuid:name" identifier
    # for fleet-source rows (see SQLModelRepository.list_running_deckies).
    assert rows[0]["dst_decky_uuid"].startswith("local:fleet-")


@pytest.mark.asyncio
async def test_tick_is_noop_when_no_running_deckies(repo, fake_bus, monkeypatch):
    called = False

    async def fake_run(argv):
        nonlocal called
        called = True
        return 0, "SSH-2.0-foo", ""

    monkeypatch.setattr(ssh_driver, "_run", fake_run)

    async def fake_run_with_stdin(argv, stdin_bytes):
        # plant_file takes the base64-streaming path; treat any docker
        # exec write as a successful no-op for the integration test.
        return 0, "", ""

    monkeypatch.setattr(ssh_driver, "_run_with_stdin", fake_run_with_stdin)
    await orch_worker._one_tick(repo, fake_bus)

    assert called is False
    assert await repo.list_orchestrator_events(limit=10) == []
