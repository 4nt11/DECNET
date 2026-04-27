"""End-to-end-ish: one emailgen tick against a real SQLite repo + FakeBus,
with the Ollama + docker-exec subprocess stubbed."""
from __future__ import annotations

import json

import pytest
import pytest_asyncio

from decnet.bus.fake import FakeBus
from decnet.orchestrator.drivers import email as email_driver
from decnet.orchestrator.emailgen import worker as eg_worker
from decnet.orchestrator.emailgen.scheduler import EmailAction  # noqa: F401
from decnet.realism.llm.impl.fake import FakeBackend
from decnet.web.db.models import Topology, TopologyDecky
from decnet.web.db.sqlite.repository import SQLiteRepository


_PERSONAS = [
    {
        "name": "John Smith",
        "email": "john@corp.com",
        "role": "COO",
        "tone": "formal",
        "mannerisms": ["uses 'Best regards'"],
        "active_hours": "00:00-00:00",  # always-on so test is hour-independent
    },
    {
        "name": "Sarah Johnson",
        "email": "sarah@corp.com",
        "role": "PM",
        "tone": "direct",
        "mannerisms": ["uses bullets"],
        "active_hours": "00:00-00:00",
    },
]


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


async def _seed_mail_topology(repo: SQLiteRepository) -> str:
    async with repo._session() as session:
        topo = Topology(
            name="t-mail",
            config_snapshot="{}",
            status="active",
            email_personas=json.dumps(_PERSONAS),
            language_default="en",
        )
        session.add(topo)
        await session.commit()
        await session.refresh(topo)
        decky = TopologyDecky(
            topology_id=topo.id,
            name="mailhost",
            services=json.dumps(["imap"]),
            ip="10.0.0.10",
            state="running",
        )
        session.add(decky)
        await session.commit()
        await session.refresh(decky)
        return decky.uuid


@pytest.mark.asyncio
async def test_one_tick_records_and_publishes(repo, fake_bus, monkeypatch):
    decky_uuid = await _seed_mail_topology(repo)

    # Stub only the docker exec subprocess; the LLM call goes through
    # an injected FakeBackend with deterministic output.
    async def fake_run_capture(argv, *, stdin_data=None, timeout=8.0):
        return 0, "", ""

    monkeypatch.setattr(email_driver, "_run_capture", fake_run_capture)

    received: list = []

    async def collect():
        async with fake_bus.subscribe(f"orchestrator.email.{decky_uuid}") as sub:
            async for ev in sub:
                received.append(ev)
                return

    import asyncio
    collector = asyncio.create_task(collect())
    await asyncio.sleep(0)

    driver = email_driver.EmailDriver(
        llm=FakeBackend(output="Subject: Hi\n\nBody here.\n"),
    )
    await eg_worker._one_tick(repo, driver, fake_bus)
    await asyncio.wait_for(collector, timeout=2.0)

    rows = await repo.list_orchestrator_emails()
    assert len(rows) == 1
    row = rows[0]
    assert row["success"] is True
    assert row["mail_decky_uuid"] == decky_uuid
    assert row["subject"] == "Hi"
    assert row["language"] == "en"

    assert len(received) == 1
    assert received[0].topic == f"orchestrator.email.{decky_uuid}"
    assert received[0].payload["kind"] == "email"
    assert received[0].payload["success"] is True


@pytest.mark.asyncio
async def test_one_tick_noop_when_no_mail_decky(repo, fake_bus, monkeypatch):
    called = False

    async def fake_run_capture(argv, *, stdin_data=None, timeout=8.0):
        nonlocal called
        called = True
        return 0, "", ""

    monkeypatch.setattr(email_driver, "_run_capture", fake_run_capture)

    driver = email_driver.EmailDriver(
        llm=FakeBackend(output="Subject: x\n\nb\n"),
    )
    await eg_worker._one_tick(repo, driver, fake_bus)
    assert called is False
    assert await repo.list_orchestrator_emails() == []
