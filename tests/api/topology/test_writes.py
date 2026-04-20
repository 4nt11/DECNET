"""Phase 3 Step 3 — write endpoints: create / delete / deploy."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist, transition_status
from decnet.topology.status import TopologyStatus
from decnet.web.dependencies import repo as _repo

_V1 = "/api/v1/topologies"


def _generate_payload(name: str = "from-api") -> dict:
    return {
        "name": name,
        "depth": 1,
        "branching_factor": 1,
        "deckies_per_lan_min": 1,
        "deckies_per_lan_max": 1,
        "services_explicit": ["ssh"],
        "randomize_services": False,
        "seed": 1,
    }


def _cfg(name: str = "draft") -> TopologyConfig:
    return TopologyConfig(
        name=name,
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        services_explicit=["ssh"],
        randomize_services=False,
        seed=0,
    )


async def _seed(name: str = "draft") -> str:
    return await persist(_repo, generate(_cfg(name)))


# ── POST /topologies ──────────────────────────────────────────────


@pytest.mark.anyio
async def test_create_ok(client, auth_token):
    r = await client.post(
        f"{_V1}/",
        json=_generate_payload(),
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == TopologyStatus.PENDING
    assert body["name"] == "from-api"

    # Children were persisted.
    lans = await _repo.list_lans_for_topology(body["id"])
    assert len(lans) >= 1


@pytest.mark.anyio
async def test_create_requires_admin(client, viewer_token):
    r = await client.post(
        f"{_V1}/",
        json=_generate_payload(),
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 403


@pytest.mark.anyio
async def test_create_requires_auth(client):
    r = await client.post(f"{_V1}/", json=_generate_payload())
    assert r.status_code == 401


@pytest.mark.anyio
async def test_create_bad_body(client, auth_token):
    r = await client.post(
        f"{_V1}/",
        json={"name": "x"},  # missing required fields
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Project-wide validation handler: missing fields → 400 (not 422).
    assert r.status_code == 400


# ── DELETE /topologies/{id} ───────────────────────────────────────


@pytest.mark.anyio
async def test_delete_pending_ok(client, auth_token):
    topology_id = await _seed("for-delete")
    r = await client.delete(
        f"{_V1}/{topology_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 204
    assert await _repo.get_topology(topology_id) is None


@pytest.mark.anyio
async def test_delete_active_blocked(client, auth_token):
    topology_id = await _seed("for-delete-active")
    await transition_status(_repo, topology_id, TopologyStatus.DEPLOYING)
    await transition_status(_repo, topology_id, TopologyStatus.ACTIVE)

    r = await client.delete(
        f"{_V1}/{topology_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 409
    assert await _repo.get_topology(topology_id) is not None


@pytest.mark.anyio
async def test_delete_missing_404(client, auth_token):
    r = await client.delete(
        f"{_V1}/does-not-exist",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_delete_requires_admin(client, viewer_token):
    topology_id = await _seed("viewer-delete")
    r = await client.delete(
        f"{_V1}/{topology_id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 403


# ── POST /topologies/{id}/deploy ──────────────────────────────────


@pytest.mark.anyio
async def test_deploy_accepts_pending(client, auth_token):
    topology_id = await _seed("for-deploy")
    with patch(
        "decnet.web.router.topology.api_deploy_topology.deploy_topology",
        new=AsyncMock(return_value=None),
    ) as mock_deploy:
        r = await client.post(
            f"{_V1}/{topology_id}/deploy",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["id"] == topology_id
    # BackgroundTasks run after the response, so the mock must have been invoked
    # by the time the client context exits.
    mock_deploy.assert_called_once()


@pytest.mark.anyio
async def test_deploy_non_pending_blocked(client, auth_token):
    topology_id = await _seed("for-deploy-blocked")
    await transition_status(_repo, topology_id, TopologyStatus.DEPLOYING)

    r = await client.post(
        f"{_V1}/{topology_id}/deploy",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 409


@pytest.mark.anyio
async def test_deploy_missing_404(client, auth_token):
    r = await client.post(
        f"{_V1}/missing/deploy",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_deploy_requires_admin(client, viewer_token):
    topology_id = await _seed("viewer-deploy")
    r = await client.post(
        f"{_V1}/{topology_id}/deploy",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 403
