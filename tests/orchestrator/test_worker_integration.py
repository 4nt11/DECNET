# SPDX-License-Identifier: AGPL-3.0-or-later
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

    # plant_file delegates to decky_io.write_file_to_container; treat
    # any docker exec write as a successful no-op for the integration
    # test.
    async def fake_write_file(*a, **kw):
        return True, None

    import decnet.decky_io.write as _decky_io_write
    monkeypatch.setattr(_decky_io_write, "write_file_to_container", fake_write_file)

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

    # plant_file delegates to decky_io.write_file_to_container; treat
    # any docker exec write as a successful no-op for the integration
    # test.
    async def fake_write_file(*a, **kw):
        return True, None

    import decnet.decky_io.write as _decky_io_write
    monkeypatch.setattr(_decky_io_write, "write_file_to_container", fake_write_file)

    await orch_worker._one_tick(repo, fake_bus)

    rows = await repo.list_orchestrator_events(limit=10)
    assert len(rows) == 1
    # The dst_decky_uuid is our composite "host_uuid:name" identifier
    # for fleet-source rows (see SQLModelRepository.list_running_deckies).
    assert rows[0]["dst_decky_uuid"].startswith("local:fleet-")


@pytest.mark.asyncio
async def test_one_tick_email_branch_records_orchestrator_email(
    repo, fake_bus, monkeypatch,
):
    """Stage 5 contract: email actions land via the unified orchestrator.

    The pre-collapse path was a separate ``decnet emailgen run`` worker;
    after the realism migration the orchestrator's tick handles email
    drops alongside traffic + file via the action-kind roll.  This test
    seeds a topology with a mail decky + two personas, forces the
    action roll to ``email``, stubs the LLM + docker-exec write paths,
    and verifies an ``orchestrator_emails`` row + bus event land.
    """
    import json
    from decnet.orchestrator.drivers import email as email_driver
    from decnet.realism.llm.impl.fake import FakeBackend

    personas = [
        {
            "name": "John Smith", "email": "john@corp.com", "role": "COO",
            "tone": "formal", "mannerisms": ["uses 'Best regards'"],
            "active_hours": "00:00-00:00",
        },
        {
            "name": "Sarah Johnson", "email": "sarah@corp.com", "role": "PM",
            "tone": "direct", "mannerisms": ["uses bullets"],
            "active_hours": "00:00-00:00",
        },
    ]
    async with repo._session() as session:
        topo = Topology(
            name="t-email", config_snapshot="{}", status="active",
            email_personas=json.dumps(personas),
        )
        session.add(topo)
        await session.commit()
        await session.refresh(topo)
        mail_decky = TopologyDecky(
            topology_id=topo.id, name="mailhost",
            services=json.dumps(["imap"]), ip="10.0.0.5", state="running",
        )
        session.add(mail_decky)
        await session.commit()

    # Force the worker's action roll to the email branch — no SSH-capable
    # deckies exist in this seed (only IMAP), so traffic/file drop to
    # None and email is the only viable branch anyway, but we pin the
    # roll for determinism.
    monkeypatch.setattr(orch_worker, "_roll_action_kind", lambda _rng: "email")

    # Stub the LLM so we don't shell out to ollama. The driver
    # constructs its own backend in __init__; we patch get_driver_for
    # to return a driver with a FakeBackend pre-injected.
    fake_eml = (
        "Subject: Q3 ops review\n\n"
        "Hi Sarah,\n\nQuick note on the Q3 review.\n\nBest regards,\nJohn\n"
    )
    fake_llm = FakeBackend(output=fake_eml)
    fake_driver = email_driver.EmailDriver(llm=fake_llm)

    def _factory(action):
        from decnet.orchestrator.emailgen.scheduler import EmailAction as _EA
        if isinstance(action, _EA):
            return fake_driver
        from decnet.orchestrator.drivers import get_driver_for as _real
        return _real(action)

    monkeypatch.setattr(orch_worker, "get_driver_for", _factory)

    # Stub the docker-exec write path on the email driver — same trick
    # the SSH driver tests use, but EmailDriver shells out via plain
    # asyncio.create_subprocess_exec.
    async def fake_create(*args, **kwargs):
        class _Stub:
            returncode = 0
            async def communicate(self, _stdin=None):
                return b"", b""
        return _Stub()

    import asyncio as _asyncio
    monkeypatch.setattr(_asyncio, "create_subprocess_exec", fake_create)

    received: list = []
    async def collect():
        async with fake_bus.subscribe("orchestrator.>") as sub:
            async for ev in sub:
                received.append(ev)
                if len(received) >= 1:
                    return
    collector = _asyncio.create_task(collect())
    await _asyncio.sleep(0)

    await orch_worker._one_tick(repo, fake_bus)
    await _asyncio.wait_for(collector, timeout=2.0)

    # The email branch lands in orchestrator_emails, NOT
    # orchestrator_events — separate table, separate kind discriminant.
    emails = await repo.list_orchestrator_emails(limit=10)
    assert len(emails) == 1
    row = emails[0]
    assert row["mail_decky_uuid"] == mail_decky.uuid
    assert row["sender_email"] in {"john@corp.com", "sarah@corp.com"}
    assert row["recipient_email"] in {"john@corp.com", "sarah@corp.com"}
    assert row["sender_email"] != row["recipient_email"]
    assert row["subject"]
    assert row["success"] is True

    # Bus event topic discriminator + payload kind agree.
    assert len(received) == 1
    ev = received[0]
    assert ev.topic.startswith("orchestrator.email.")
    assert ev.payload["kind"] == "email"
    assert ev.payload["mail_decky_uuid"] == mail_decky.uuid


@pytest.mark.asyncio
async def test_smtp_probe_listener_get_bus_raises_no_unbound_error(
    repo, monkeypatch,
) -> None:
    """BUG-7 regression: if get_bus() raises, the finally block must not
    produce an UnboundLocalError on ``bus``; the function must return
    cleanly (RuntimeError is logged+swallowed by the outer except handler)."""
    import asyncio
    from decnet.orchestrator import worker as _w

    def bad_get_bus(**_kw):
        raise RuntimeError("bus factory unavailable")

    monkeypatch.setattr(_w, "get_bus", bad_get_bus)

    shutdown = asyncio.Event()
    shutdown.set()

    # Before fix: UnboundLocalError escaped from finally because ``bus``
    # was never assigned.  After fix: completes without any exception.
    await _w._run_smtp_probe_listener(repo, shutdown)


@pytest.mark.asyncio
async def test_tick_is_noop_when_no_running_deckies(repo, fake_bus, monkeypatch):
    called = False

    async def fake_run(argv):
        nonlocal called
        called = True
        return 0, "SSH-2.0-foo", ""

    monkeypatch.setattr(ssh_driver, "_run", fake_run)

    # plant_file delegates to decky_io.write_file_to_container; treat
    # any docker exec write as a successful no-op for the integration
    # test.
    async def fake_write_file(*a, **kw):
        return True, None

    import decnet.decky_io.write as _decky_io_write
    monkeypatch.setattr(_decky_io_write, "write_file_to_container", fake_write_file)
    await orch_worker._one_tick(repo, fake_bus)

    assert called is False
    assert await repo.list_orchestrator_events(limit=10) == []
