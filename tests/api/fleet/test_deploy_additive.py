# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST /deckies/deploy additive vs replace_fleet semantics.

Default behaviour (replace_fleet=False) appends the INI to the existing
fleet so the wizard's "deploy one more decky" submit no longer wipes
prior deckies. replace_fleet=True preserves the historical
set-desired-state semantics for CLI / declarative callers.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

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


@pytest.fixture(autouse=True)
async def _isolate_state():
    for row in await repo.list_swarm_hosts():
        await repo.delete_swarm_host(row["uuid"])
    await repo.set_state("deployment", None)
    yield
    await repo.set_state("deployment", None)


@pytest.mark.anyio
async def test_additive_default_appends_to_existing_fleet(client, auth_token, monkeypatch):
    """Two sequential deploys with replace_fleet unset → both deckies in state."""
    monkeypatch.setenv("DECNET_MODE", "master")

    r1 = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-01]\nservices = ssh\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r1.status_code == 202, r1.text

    r2 = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-02]\nservices = http\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r2.status_code == 202, r2.text

    committed = await repo.get_state("deployment")
    assert committed is not None
    names = {d["name"] for d in committed["config"]["deckies"]}
    assert names == {"decky-01", "decky-02"}


@pytest.mark.anyio
async def test_additive_name_collision_returns_409(client, auth_token, monkeypatch):
    """Re-submitting an existing decky name without replace_fleet → 409."""
    monkeypatch.setenv("DECNET_MODE", "master")

    r1 = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-01]\nservices = ssh\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r1.status_code == 202, r1.text

    r2 = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-01]\nservices = http\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r2.status_code == 409, r2.text
    assert "decky-01" in r2.json()["detail"]
    assert "replace_fleet" in r2.json()["detail"]


@pytest.mark.anyio
async def test_additive_ip_collision_returns_409(client, auth_token, monkeypatch):
    """A new decky pinned to an IP already in use → 409 with the IP."""
    monkeypatch.setenv("DECNET_MODE", "master")

    r1 = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-01]\nservices = ssh\nip = 192.168.1.50\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r1.status_code == 202, r1.text

    r2 = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-02]\nservices = http\nip = 192.168.1.50\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r2.status_code == 409, r2.text
    assert "192.168.1.50" in r2.json()["detail"]


@pytest.mark.anyio
async def test_replace_fleet_true_overwrites_existing(client, auth_token, monkeypatch):
    """replace_fleet=True preserves the historical full-replace semantics."""
    monkeypatch.setenv("DECNET_MODE", "master")

    r1 = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-01]\nservices = ssh\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r1.status_code == 202, r1.text

    r2 = await client.post(
        "/api/v1/deckies/deploy",
        json={
            "ini_content": "[decky-02]\nservices = http\n",
            "replace_fleet": True,
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r2.status_code == 202, r2.text

    committed = await repo.get_state("deployment")
    assert committed is not None
    names = {d["name"] for d in committed["config"]["deckies"]}
    assert names == {"decky-02"}


@pytest.mark.anyio
async def test_additive_lifecycle_ids_scoped_to_new_deckies(client, auth_token, monkeypatch):
    """In additive mode the response's lifecycle_ids cover only the deckies
    the caller submitted, not carryover. Operators polling
    /deckies/lifecycle?ids=... see exactly what this call deployed."""
    monkeypatch.setenv("DECNET_MODE", "master")

    r1 = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-01]\nservices = ssh\n[decky-02]\nservices = http\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r1.status_code == 202, r1.text
    assert len(r1.json()["lifecycle_ids"]) == 2

    r2 = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-03]\nservices = ssh\n"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r2.status_code == 202, r2.text
    body2 = r2.json()
    assert len(body2["lifecycle_ids"]) == 1

    committed = await repo.get_state("deployment")
    assert committed is not None
    names = {d["name"] for d in committed["config"]["deckies"]}
    assert names == {"decky-01", "decky-02", "decky-03"}
