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


# ── mode / target_host_uuid pairing (Step 1) ──────────────────────


async def _seed_swarm_host(uuid_: str = "host-uuid-1", status: str = "enrolled") -> None:
    await _repo.add_swarm_host(
        {
            "uuid": uuid_,
            "name": f"host-{uuid_}",
            "address": "10.9.9.9",
            "agent_port": 8765,
            "status": status,
            "client_cert_fingerprint": "a" * 64,
            "cert_bundle_path": "/tmp/ignored",
        }
    )


@pytest.mark.anyio
async def test_create_blank_agent_mode_ok(client, auth_token):
    await _seed_swarm_host("host-ok", status="active")
    r = await client.post(
        f"{_V1}/blank",
        json={"name": "blank-agent", "mode": "agent", "target_host_uuid": "host-ok"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["mode"] == "agent"
    assert body["target_host_uuid"] == "host-ok"


@pytest.mark.anyio
async def test_create_blank_agent_without_host_is_400(client, auth_token):
    r = await client.post(
        f"{_V1}/blank",
        json={"name": "blank-agent-no-host", "mode": "agent"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 400
    assert "target_host_uuid" in r.json()["detail"]


@pytest.mark.anyio
async def test_create_blank_agent_unknown_host_is_400(client, auth_token):
    r = await client.post(
        f"{_V1}/blank",
        json={
            "name": "blank-agent-unknown",
            "mode": "agent",
            "target_host_uuid": "does-not-exist",
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 400
    assert "unknown" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_create_blank_unihost_with_host_is_400(client, auth_token):
    await _seed_swarm_host("host-unused")
    r = await client.post(
        f"{_V1}/blank",
        json={
            "name": "blank-unihost-with-host",
            "mode": "unihost",
            "target_host_uuid": "host-unused",
        },
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_create_agent_mode_ok(client, auth_token):
    await _seed_swarm_host("host-gen")
    payload = {
        **_generate_payload("gen-agent"),
        "mode": "agent",
        "target_host_uuid": "host-gen",
    }
    r = await client.post(
        f"{_V1}/",
        json=payload,
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["mode"] == "agent"
    assert body["target_host_uuid"] == "host-gen"


@pytest.mark.anyio
async def test_create_agent_unreachable_host_is_400(client, auth_token):
    await _seed_swarm_host("host-dead", status="unreachable")
    payload = {
        **_generate_payload("gen-agent-dead"),
        "mode": "agent",
        "target_host_uuid": "host-dead",
    }
    r = await client.post(
        f"{_V1}/",
        json=payload,
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 400
