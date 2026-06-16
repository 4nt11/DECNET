# SPDX-License-Identifier: AGPL-3.0-or-later
"""Swarm propagation coverage for services_live.

Three mutation paths (add / remove / update_config) need to re-dispatch the
host's shard via ``AgentClient.deploy`` instead of running master-local
docker-compose, because the master has no containers for swarm deckies.

These tests stub ``_load_state``, ``_compose``, and ``dispatch_decnet_config``
so we can assert the routing decisions without spinning up a real worker.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, AsyncIterator
from datetime import datetime, timezone

import pytest
import pytest_asyncio

from decnet.bus.fake import FakeBus
from decnet.engine import services_live
from decnet.models import DecnetConfig, DeckyConfig
from decnet.web.db.sqlite.repository import SQLiteRepository
import decnet.web.db.models  # noqa: F401  — register tables


@pytest_asyncio.fixture
async def repo(tmp_path: Path) -> AsyncIterator[SQLiteRepository]:
    r = SQLiteRepository(str(tmp_path / "p.db"))
    await r.initialize()
    yield r


@pytest_asyncio.fixture
async def fake_bus(monkeypatch) -> AsyncIterator[FakeBus]:
    bus = FakeBus()
    await bus.connect()
    from decnet.bus import factory
    monkeypatch.setattr(factory, "get_bus", lambda: bus)
    yield bus
    await bus.close()


def _make_decky(name: str, host_uuid: str | None) -> DeckyConfig:
    """Build a minimally-valid DeckyConfig for state-fixture purposes."""
    return DeckyConfig(
        name=name,
        ip="10.0.0.5",
        services=["ssh"],
        distro="debian",
        base_image="debian:bookworm-slim",
        hostname=name,
        host_uuid=host_uuid,
    )


def _make_state(decky: DeckyConfig) -> tuple[DecnetConfig, Path]:
    cfg = DecnetConfig(
        mode="swarm" if decky.host_uuid else "unihost",
        interface="eth0",
        subnet="10.0.0.0/24",
        gateway="10.0.0.1",
        deckies=[decky],
    )
    return cfg, Path("/tmp/decnet-compose.yml")


@pytest_asyncio.fixture
async def swarm_fleet_decky(repo: SQLiteRepository) -> dict:
    """Persist one SwarmHost + one DeckyShard for tests to mutate."""
    host_uuid = "host-uuid-1"
    await repo.add_swarm_host({
        "uuid": host_uuid,
        "name": "worker-01",
        "address": "10.99.0.5",
        "agent_port": 8765,
        "status": "active",
        "client_cert_fingerprint": "deadbeef" * 8,
        "cert_bundle_path": "/tmp/bundle",
        "enrolled_at": datetime.now(timezone.utc),
    })
    decky = _make_decky("web1", host_uuid)
    await repo.upsert_decky_shard({
        "decky_name": decky.name,
        "host_uuid": host_uuid,
        "services": '["ssh"]',
        "decky_config": decky.model_dump_json(),
        "decky_ip": decky.ip,
        "state": "running",
        "updated_at": datetime.now(timezone.utc),
    })
    return {"host_uuid": host_uuid, "decky": decky}


@pytest_asyncio.fixture
async def local_fleet_decky() -> DeckyConfig:
    """Decky without a host_uuid — purely local."""
    return _make_decky("local1", None)


def _patch_no_state_writes(monkeypatch) -> list[tuple]:
    """Stub the disk-touching helpers so tests don't write a real state file."""
    captured_compose: list[tuple] = []
    monkeypatch.setattr(services_live, "_save_state", lambda *a, **kw: None)
    monkeypatch.setattr(services_live, "_write_compose", lambda *a, **kw: None)
    monkeypatch.setattr(
        services_live, "_compose",
        lambda *a, **kw: captured_compose.append(a),
    )
    return captured_compose


# --------------------------- swarm fleet add --------------------------------


@pytest.mark.asyncio
async def test_swarm_fleet_add_service_redispatches_and_skips_local_compose(
    repo: SQLiteRepository, swarm_fleet_decky: dict, fake_bus: FakeBus,
    monkeypatch,
) -> None:
    captured_compose = _patch_no_state_writes(monkeypatch)
    decky = swarm_fleet_decky["decky"]
    state = _make_state(decky)
    monkeypatch.setattr(services_live, "_load_state", lambda: state)

    dispatched: list[DecnetConfig] = []

    async def fake_dispatch(config, repo_, dry_run=False, no_cache=False):
        dispatched.append(config)
        from decnet.web.db.models import SwarmDeployResponse
        return SwarmDeployResponse(results=[])

    # services_live imports lazily inside _redispatch_fleet_shard.
    monkeypatch.setattr(
        "decnet.web.router.swarm.api_deploy_swarm.dispatch_decnet_config",
        fake_dispatch,
    )

    await services_live.add_service(
        repo, decky_kind="fleet",
        decky_name=decky.name, service_name="rdp",
    )
    # Local _compose was NOT called for the swarm decky.
    assert captured_compose == []
    # Dispatch was called with a config containing only the host's deckies.
    assert len(dispatched) == 1
    sent = dispatched[0]
    assert all(d.host_uuid == swarm_fleet_decky["host_uuid"] for d in sent.deckies)
    assert any(d.name == decky.name for d in sent.deckies)


# --------------------------- swarm fleet remove -----------------------------


@pytest.mark.asyncio
async def test_swarm_fleet_remove_service_redispatches_and_skips_local_compose(
    repo: SQLiteRepository, swarm_fleet_decky: dict, fake_bus: FakeBus,
    monkeypatch,
) -> None:
    captured_compose = _patch_no_state_writes(monkeypatch)
    decky = swarm_fleet_decky["decky"]
    state = _make_state(decky)
    monkeypatch.setattr(services_live, "_load_state", lambda: state)

    dispatched: list[Any] = []

    async def fake_dispatch(config, repo_, dry_run=False, no_cache=False):
        dispatched.append(config)
        from decnet.web.db.models import SwarmDeployResponse
        return SwarmDeployResponse(results=[])

    monkeypatch.setattr(
        "decnet.web.router.swarm.api_deploy_swarm.dispatch_decnet_config",
        fake_dispatch,
    )

    await services_live.remove_service(
        repo, decky_kind="fleet",
        decky_name=decky.name, service_name="ssh",  # currently on
    )
    # No master-local stop / rm — those would no-op anyway, save the syscalls.
    assert captured_compose == []
    assert len(dispatched) == 1


# --------------------------- swarm fleet update_config ----------------------


@pytest.mark.asyncio
async def test_swarm_fleet_update_config_apply_redispatches(
    repo: SQLiteRepository, swarm_fleet_decky: dict, fake_bus: FakeBus,
    monkeypatch,
) -> None:
    captured_compose = _patch_no_state_writes(monkeypatch)
    decky = swarm_fleet_decky["decky"]
    state = _make_state(decky)
    monkeypatch.setattr(services_live, "_load_state", lambda: state)

    dispatched: list[Any] = []

    async def fake_dispatch(config, repo_, dry_run=False, no_cache=False):
        dispatched.append(config)
        from decnet.web.db.models import SwarmDeployResponse
        return SwarmDeployResponse(results=[])

    monkeypatch.setattr(
        "decnet.web.router.swarm.api_deploy_swarm.dispatch_decnet_config",
        fake_dispatch,
    )

    await services_live.update_service_config(
        repo, decky_kind="fleet",
        decky_name=decky.name, service_name="ssh",
        cfg={"password": "hunter2"}, apply=True,
    )
    assert captured_compose == []
    assert len(dispatched) == 1


@pytest.mark.asyncio
async def test_swarm_fleet_update_config_save_only_does_not_redispatch(
    repo: SQLiteRepository, swarm_fleet_decky: dict, fake_bus: FakeBus,
    monkeypatch,
) -> None:
    """``apply=False`` means Save: persist but don't recreate. No redispatch
    either — the worker keeps its current containers running their old env."""
    _patch_no_state_writes(monkeypatch)
    decky = swarm_fleet_decky["decky"]
    state = _make_state(decky)
    monkeypatch.setattr(services_live, "_load_state", lambda: state)

    dispatched: list[Any] = []

    async def fake_dispatch(*a, **kw):
        dispatched.append(a)
        from decnet.web.db.models import SwarmDeployResponse
        return SwarmDeployResponse(results=[])

    monkeypatch.setattr(
        "decnet.web.router.swarm.api_deploy_swarm.dispatch_decnet_config",
        fake_dispatch,
    )

    await services_live.update_service_config(
        repo, decky_kind="fleet",
        decky_name=decky.name, service_name="ssh",
        cfg={"password": "hunter2"}, apply=False,
    )
    assert dispatched == []


# --------------------------- local-only path stays local -------------------


@pytest.mark.asyncio
async def test_local_fleet_add_service_runs_local_compose_no_dispatch(
    repo: SQLiteRepository, local_fleet_decky: DeckyConfig, fake_bus: FakeBus,
    monkeypatch,
) -> None:
    """Decky with no host_uuid → no DeckyShard row → master keeps running
    docker-compose locally and skips the dispatch path entirely."""
    captured_compose = _patch_no_state_writes(monkeypatch)
    state = _make_state(local_fleet_decky)
    monkeypatch.setattr(services_live, "_load_state", lambda: state)

    dispatched: list[Any] = []

    async def fake_dispatch(*a, **kw):
        dispatched.append(a)
        from decnet.web.db.models import SwarmDeployResponse
        return SwarmDeployResponse(results=[])

    monkeypatch.setattr(
        "decnet.web.router.swarm.api_deploy_swarm.dispatch_decnet_config",
        fake_dispatch,
    )

    await services_live.add_service(
        repo, decky_kind="fleet",
        decky_name=local_fleet_decky.name, service_name="rdp",
    )
    # Local compose ran (up -d --no-deps --build local1-rdp).
    assert any("up" in c and f"{local_fleet_decky.name}-rdp" in c for c in captured_compose)
    # AgentClient was NOT called.
    assert dispatched == []
