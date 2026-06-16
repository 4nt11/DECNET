# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST /deckies/deploy additive vs replace_fleet semantics.

Default behaviour (replace_fleet=False) appends the INI to the existing
fleet so the wizard's "deploy one more decky" submit no longer wipes
prior deckies. replace_fleet=True preserves the historical
set-desired-state semantics for CLI / declarative callers.

The existing fleet is read from fleet_deckies — the engine-mirrored table
written on every deploy/teardown (CLI or web), per the source-of-truth
model in fleet/reconciler.py. These tests seed fleet_deckies directly,
which also models the BUG-2 scenario: a fleet established out of band
(CLI/seed) that the web deploy guard must see and append to rather than
wipe. See development/ADR-001-FLEET-SOURCE-OF-TRUTH.md.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from decnet.config import DeckyConfig
from decnet.web.db.models import LOCAL_HOST_SENTINEL
from decnet.web.dependencies import repo


@pytest.fixture(autouse=True)
def contract_test_mode(monkeypatch):
    monkeypatch.setenv("DECNET_CONTRACT_TEST", "true")


@pytest.fixture(autouse=True)
def mock_network():
    with patch("decnet.web.router.fleet.api_deploy_deckies.get_host_ip", return_value="192.168.1.100"):
        with patch("decnet.web.router.fleet.api_deploy_deckies.detect_interface", return_value="eth0"):
            with patch("decnet.web.router.fleet.api_deploy_deckies.detect_subnet", return_value=("192.168.1.0/24", "192.168.1.1")):
                yield


async def _clear_fleet() -> None:
    for row in await repo.list_fleet_deckies():
        await repo.delete_fleet_decky(
            host_uuid=row.get("host_uuid") or LOCAL_HOST_SENTINEL,
            name=row["name"],
        )


async def _seed_fleet(name: str, *, ip: str = "192.168.1.10", services=("ssh",)) -> None:
    """Insert a decky into fleet_deckies, as the engine mirror does on a
    CLI/web deploy. Stamps a full DeckyConfig into decky_config so the deploy
    guard can rehydrate it."""
    cfg = DeckyConfig(
        name=name,
        ip=ip,
        services=list(services),
        distro="debian",
        base_image="debian:bookworm-slim",
        hostname=name,
    )
    await repo.upsert_fleet_decky({
        "host_uuid": LOCAL_HOST_SENTINEL,
        "name": name,
        "services": list(services),
        "decky_config": cfg.model_dump(mode="json"),
        "decky_ip": ip,
        "state": "running",
    })


@pytest.fixture(autouse=True)
async def _isolate_state():
    for row in await repo.list_swarm_hosts():
        await repo.delete_swarm_host(row["uuid"])
    await repo.set_state("deployment", None)
    await _clear_fleet()
    yield
    await repo.set_state("deployment", None)
    await _clear_fleet()


@pytest.mark.anyio
async def test_additive_onto_existing_fleet_appends_not_wipes(client, auth_token, monkeypatch):
    """BUG-2 regression: an additive web deploy onto a fleet established out
    of band (CLI/seed → fleet_deckies) appends rather than wiping it.

    Previously the guard read State["deployment"] (empty for a CLI-seeded
    fleet), so existing_deckies was [] and the reconciler tore the running
    fleet down to the single submitted decky."""
    monkeypatch.setenv("DECNET_MODE", "master")
    await _seed_fleet("decky-01", ip="192.168.1.10")

    r = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-02]\nservices = http\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 202, r.text

    names = {d["name"] for d in await repo.get_deckies()}
    assert names == {"decky-01", "decky-02"}


@pytest.mark.anyio
async def test_additive_name_collision_returns_409(client, auth_token, monkeypatch):
    """Submitting a decky whose name already exists in the fleet without
    replace_fleet → 409."""
    monkeypatch.setenv("DECNET_MODE", "master")
    await _seed_fleet("decky-01")

    r = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-01]\nservices = http\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 409, r.text
    assert "decky-01" in r.json()["detail"]
    assert "replace_fleet" in r.json()["detail"]


@pytest.mark.anyio
async def test_additive_ip_collision_returns_409(client, auth_token, monkeypatch):
    """A new decky pinned to an IP already in use by the existing fleet → 409
    with the IP."""
    monkeypatch.setenv("DECNET_MODE", "master")
    await _seed_fleet("decky-01", ip="192.168.1.50")

    r = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-02]\nservices = http\nip = 192.168.1.50\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 409, r.text
    assert "192.168.1.50" in r.json()["detail"]


@pytest.mark.anyio
async def test_replace_fleet_true_overwrites_existing(client, auth_token, monkeypatch):
    """replace_fleet=True preserves the historical full-replace semantics:
    the existing fleet is dropped and the committed inventory is exactly the
    submitted INI."""
    monkeypatch.setenv("DECNET_MODE", "master")
    await _seed_fleet("decky-01")

    r = await client.post(
        "/api/v1/deckies/deploy",
        json={
            "ini_content": "[decky-02]\nservices = http\n",
            "replace_fleet": True,
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 202, r.text

    names = {d["name"] for d in await repo.get_deckies()}
    assert names == {"decky-02"}


@pytest.mark.anyio
async def test_additive_lifecycle_ids_scoped_to_new_deckies(client, auth_token, monkeypatch):
    """In additive mode the response's lifecycle_ids cover only the deckies
    the caller submitted, not carryover. Operators polling
    /deckies/lifecycle?ids=... see exactly what this call deployed."""
    monkeypatch.setenv("DECNET_MODE", "master")
    await _seed_fleet("decky-01", ip="192.168.1.10")
    await _seed_fleet("decky-02", ip="192.168.1.11")

    r = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-03]\nservices = ssh\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 202, r.text
    assert len(r.json()["lifecycle_ids"]) == 1

    names = {d["name"] for d in await repo.get_deckies()}
    assert names == {"decky-01", "decky-02", "decky-03"}
