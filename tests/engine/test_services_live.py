"""Unit coverage for engine.services_live add/remove flows.

We don't shell out to docker — :func:`engine.deployer._compose` is
patched to a no-op recorder.  The DB (SQLite) and the topology
hydrator run for real so the persistence path is exercised end-to-end.
"""
from __future__ import annotations

import json
from typing import AsyncIterator

import pytest
import pytest_asyncio

from decnet.bus.fake import FakeBus
from decnet.engine import services_live
from decnet.engine.services_live import ServiceMutationError
from decnet.web.db.sqlite.repository import SQLiteRepository
import decnet.web.db.models  # noqa: F401  — register tables


@pytest_asyncio.fixture
async def repo(tmp_path) -> AsyncIterator[SQLiteRepository]:
    r = SQLiteRepository(str(tmp_path / "p.db"))
    await r.initialize()
    yield r


@pytest_asyncio.fixture
async def fake_bus(monkeypatch) -> AsyncIterator[FakeBus]:
    bus = FakeBus()
    await bus.connect()
    # services_live publishes via get_bus(); rebind to the fake.
    from decnet.bus import factory
    monkeypatch.setattr(factory, "get_bus", lambda: bus)
    yield bus
    await bus.close()


@pytest_asyncio.fixture
async def topology_with_decky(repo: SQLiteRepository) -> dict:
    """Persist one topology + one decky and return the IDs."""
    topo_id = await repo.create_topology({
        "name": "test-topo", "description": "",
    })
    decky_uuid = await repo.create_topology_decky({
        "topology_id": topo_id,
        "name": "web1",
        "ip": "10.0.0.5",
        "decky_config": {"name": "web1", "ips_by_lan": {}},
        "services": ["http"],
        "state": "running",
    })
    return {"topology_id": topo_id, "decky_uuid": decky_uuid}


# ---------------- topology add --------------------------------------------


@pytest.mark.asyncio
async def test_topology_add_service_persists_and_runs_compose_up(
    repo: SQLiteRepository, topology_with_decky: dict, fake_bus: FakeBus,
    monkeypatch, tmp_path,
) -> None:
    captured: list[tuple[str, ...]] = []

    def fake_compose(*args, compose_file=None, env=None):
        captured.append(args)

    monkeypatch.setattr(services_live, "_compose", fake_compose)
    # Avoid touching the real per-topology compose file path on disk.
    monkeypatch.setattr(
        services_live, "_topology_compose_path",
        lambda topo_id: tmp_path / f"compose-{topo_id[:8]}.yml",
    )
    sub = fake_bus.subscribe("decky.>")
    services = await services_live.add_service(
        repo, decky_kind="topology",
        topology_id=topology_with_decky["topology_id"],
        decky_name="web1", service_name="ssh",
    )
    assert services == ["http", "ssh"]
    # Compose up was called targeting just the new service container.
    assert captured and captured[0][:5] == (
        "up", "-d", "--no-deps", "--build", "web1-ssh",
    )
    # Persisted to the DB.
    row = await repo.get_topology_decky(topology_with_decky["decky_uuid"])
    persisted_services = json.loads(row["services"]) if isinstance(row["services"], str) else row["services"]
    assert "ssh" in persisted_services
    # Bus event published.
    import asyncio
    event = await asyncio.wait_for(sub.__anext__(), timeout=1.0)
    assert event.topic == "decky.web1.service.added"
    assert event.payload["service_name"] == "ssh"
    assert event.payload["topology_id"] == topology_with_decky["topology_id"]


@pytest.mark.asyncio
async def test_topology_add_service_rejects_unknown(
    repo: SQLiteRepository, topology_with_decky: dict, fake_bus: FakeBus,
) -> None:
    with pytest.raises(ServiceMutationError, match="unknown service"):
        await services_live.add_service(
            repo, decky_kind="topology",
            topology_id=topology_with_decky["topology_id"],
            decky_name="web1", service_name="not-a-real-service",
        )


@pytest.mark.asyncio
async def test_topology_add_service_rejects_duplicate(
    repo: SQLiteRepository, topology_with_decky: dict, fake_bus: FakeBus,
    monkeypatch, tmp_path,
) -> None:
    monkeypatch.setattr(services_live, "_compose", lambda *a, **kw: None)
    monkeypatch.setattr(
        services_live, "_topology_compose_path",
        lambda topo_id: tmp_path / f"compose-{topo_id[:8]}.yml",
    )
    with pytest.raises(ServiceMutationError, match="already on"):
        await services_live.add_service(
            repo, decky_kind="topology",
            topology_id=topology_with_decky["topology_id"],
            decky_name="web1", service_name="http",  # already on
        )


@pytest.mark.asyncio
async def test_topology_add_service_404_decky_not_in_topology(
    repo: SQLiteRepository, topology_with_decky: dict, fake_bus: FakeBus,
) -> None:
    with pytest.raises(ServiceMutationError, match="not in topology"):
        await services_live.add_service(
            repo, decky_kind="topology",
            topology_id=topology_with_decky["topology_id"],
            decky_name="ghost", service_name="ssh",
        )


# ---------------- topology remove -----------------------------------------


@pytest.mark.asyncio
async def test_topology_remove_service_runs_stop_then_rm(
    repo: SQLiteRepository, topology_with_decky: dict, fake_bus: FakeBus,
    monkeypatch, tmp_path,
) -> None:
    captured: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        services_live, "_compose",
        lambda *a, **kw: captured.append(a),
    )
    monkeypatch.setattr(
        services_live, "_topology_compose_path",
        lambda topo_id: tmp_path / f"compose-{topo_id[:8]}.yml",
    )
    services = await services_live.remove_service(
        repo, decky_kind="topology",
        topology_id=topology_with_decky["topology_id"],
        decky_name="web1", service_name="http",
    )
    assert services == []
    # Stop, then rm -f, in that order.
    assert captured[0] == ("stop", "web1-http")
    assert captured[1] == ("rm", "-f", "web1-http")


@pytest.mark.asyncio
async def test_topology_remove_service_rejects_when_absent(
    repo: SQLiteRepository, topology_with_decky: dict, fake_bus: FakeBus,
) -> None:
    with pytest.raises(ServiceMutationError, match="not on"):
        await services_live.remove_service(
            repo, decky_kind="topology",
            topology_id=topology_with_decky["topology_id"],
            decky_name="web1", service_name="ssh",  # not on
        )


# ---------------- service registry validation -----------------------------


def test_validate_rejects_fleet_singleton_services() -> None:
    """``fleet_singleton`` services run once fleet-wide, not per-decky."""
    from decnet.services.registry import all_services
    singletons = [
        name for name, svc in all_services().items() if svc.fleet_singleton
    ]
    if not singletons:
        pytest.skip("no fleet_singleton services registered")
    name = singletons[0]
    with pytest.raises(ServiceMutationError, match="fleet_singleton"):
        services_live._validate_service_for_per_decky(name)


def test_validate_accepts_per_decky_service() -> None:
    svc = services_live._validate_service_for_per_decky("ssh")
    assert svc.name == "ssh"
