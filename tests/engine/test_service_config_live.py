"""Engine-layer coverage for services_live.update_service_config.

Mirrors test_services_live.py — _compose patched to a recorder, real
SQLite + topology hydrator under test.
"""
from __future__ import annotations

import json
from typing import AsyncIterator

import pytest
import pytest_asyncio

from decnet.bus.fake import FakeBus
from decnet.engine import services_live
from decnet.engine.services_live import ServiceMutationError
from decnet.services.base import ConfigValidationError
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
    from decnet.bus import factory
    monkeypatch.setattr(factory, "get_bus", lambda: bus)
    yield bus
    await bus.close()


@pytest_asyncio.fixture
async def topology_with_ssh_decky(repo: SQLiteRepository) -> dict:
    topo_id = await repo.create_topology({"name": "topo", "description": ""})
    decky_uuid = await repo.add_topology_decky({
        "topology_id": topo_id,
        "name": "web1",
        "ip": "10.0.0.5",
        "decky_config": {"name": "web1", "ips_by_lan": {}},
        "services": ["ssh"],
        "state": "running",
    })
    return {"topology_id": topo_id, "decky_uuid": decky_uuid}


@pytest.mark.asyncio
async def test_update_persists_validated_cfg_no_recreate_on_save(
    repo: SQLiteRepository, topology_with_ssh_decky: dict, fake_bus: FakeBus,
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

    validated = await services_live.update_service_config(
        repo,
        decky_kind="topology",
        topology_id=topology_with_ssh_decky["topology_id"],
        decky_name="web1",
        service_name="ssh",
        cfg={"password": "hunter2", "wat": "drop me"},
        apply=False,
    )
    # Unknown key dropped.
    assert validated == {"password": "hunter2"}
    # Persisted into the decky_config blob.
    rows = await repo.list_topology_deckies(
        topology_with_ssh_decky["topology_id"]
    )
    row = next(r for r in rows if r.uuid == topology_with_ssh_decky["decky_uuid"])
    cfg_blob = row.decky_config
    if isinstance(cfg_blob, str):
        cfg_blob = json.loads(cfg_blob)
    assert cfg_blob["service_config"]["ssh"] == {"password": "hunter2"}
    # Save-only: no compose force-recreate ran.
    assert not any("--force-recreate" in a for a in captured)


@pytest.mark.asyncio
async def test_apply_runs_force_recreate(
    repo: SQLiteRepository, topology_with_ssh_decky: dict, fake_bus: FakeBus,
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
    await services_live.update_service_config(
        repo,
        decky_kind="topology",
        topology_id=topology_with_ssh_decky["topology_id"],
        decky_name="web1",
        service_name="ssh",
        cfg={"password": "hunter2"},
        apply=True,
    )
    # Apply path issued compose up --force-recreate <decky>-<svc>.
    assert any(
        "--force-recreate" in a and "web1-ssh" in a
        for a in captured
    )


@pytest.mark.asyncio
async def test_update_rejects_service_not_on_decky(
    repo: SQLiteRepository, topology_with_ssh_decky: dict, fake_bus: FakeBus,
) -> None:
    with pytest.raises(ServiceMutationError):
        await services_live.update_service_config(
            repo,
            decky_kind="topology",
            topology_id=topology_with_ssh_decky["topology_id"],
            decky_name="web1",
            service_name="http",  # not on the decky
            cfg={},
            apply=False,
        )


@pytest.mark.asyncio
async def test_update_rejects_bad_value_via_validator(
    repo: SQLiteRepository, topology_with_ssh_decky: dict, fake_bus: FakeBus,
    monkeypatch, tmp_path,
) -> None:
    # Add http to the decky so we can submit a bad response_code.
    monkeypatch.setattr(services_live, "_compose", lambda *a, **kw: None)
    monkeypatch.setattr(
        services_live, "_topology_compose_path",
        lambda topo_id: tmp_path / f"compose-{topo_id[:8]}.yml",
    )
    await repo.update_topology_decky(
        topology_with_ssh_decky["decky_uuid"], {"services": ["ssh", "http"]},
    )
    with pytest.raises(ConfigValidationError):
        await services_live.update_service_config(
            repo,
            decky_kind="topology",
            topology_id=topology_with_ssh_decky["topology_id"],
            decky_name="web1",
            service_name="http",
            cfg={"response_code": "not-a-number"},
            apply=False,
        )
