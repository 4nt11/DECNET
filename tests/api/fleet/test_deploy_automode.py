"""POST /deckies/deploy auto-mode: master + swarm hosts → shard to workers."""
from __future__ import annotations

from unittest.mock import patch, AsyncMock

import pytest

from decnet.web.dependencies import repo
from decnet.web.db.models import SwarmDeployResponse, SwarmHostResult


@pytest.fixture(autouse=True)
def contract_test_mode(monkeypatch):
    monkeypatch.setenv("DECNET_CONTRACT_TEST", "true")


@pytest.fixture(autouse=True)
def mock_network():
    with patch("decnet.web.router.fleet.api_deploy_deckies.get_host_ip", return_value="192.168.1.100"):
        with patch("decnet.web.router.fleet.api_deploy_deckies.detect_interface", return_value="eth0"):
            with patch("decnet.web.router.fleet.api_deploy_deckies.detect_subnet", return_value=("192.168.1.0/24", "192.168.1.1")):
                yield


@pytest.mark.anyio
async def test_deploy_automode_unihost_when_no_swarm_hosts(client, auth_token, monkeypatch):
    """No swarm hosts enrolled → local unihost deploy."""
    monkeypatch.setenv("DECNET_MODE", "master")
    for row in await repo.list_swarm_hosts():
        await repo.delete_swarm_host(row["uuid"])
    await repo.set_state("deployment", None)

    ini = "[decky-solo]\nservices = ssh\n"
    resp = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": ini},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["mode"] == "unihost"


@pytest.mark.anyio
async def test_deploy_automode_shards_when_swarm_host_enrolled(client, auth_token, monkeypatch):
    """Master + one active swarm host → swarm mode, dispatch invoked."""
    monkeypatch.setenv("DECNET_MODE", "master")
    await repo.set_state("deployment", None)

    for row in await repo.list_swarm_hosts():
        await repo.delete_swarm_host(row["uuid"])

    from datetime import datetime, timezone
    await repo.add_swarm_host({
        "uuid": "host-A",
        "name": "worker-a",
        "address": "10.0.0.50",
        "agent_port": 8765,
        "status": "active",
        "client_cert_fingerprint": "x" * 64,
        "updater_cert_fingerprint": None,
        "cert_bundle_path": "/tmp/worker-a",
        "enrolled_at": datetime.now(timezone.utc),
        "notes": "",
    })

    fake_response = SwarmDeployResponse(results=[
        SwarmHostResult(host_uuid="host-A", host_name="worker-a", ok=True, detail={})
    ])

    with patch(
        "decnet.web.router.fleet.api_deploy_deckies.dispatch_decnet_config",
        new=AsyncMock(return_value=fake_response),
    ) as mock_dispatch:
        ini = "[decky-01]\nservices = ssh\n[decky-02]\nservices = http\n"
        resp = await client.post(
            "/api/v1/deckies/deploy",
            json={"ini_content": ini},
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["mode"] == "swarm"
    assert mock_dispatch.await_count == 1
    dispatched_config = mock_dispatch.await_args.args[0]
    assert dispatched_config.mode == "swarm"
    assert all(d.host_uuid == "host-A" for d in dispatched_config.deckies)

    await repo.delete_swarm_host("host-A")


@pytest.mark.anyio
async def test_deploy_automode_resets_stale_host_uuid(client, auth_token, monkeypatch):
    """Deckies carried over from prior state must not be dispatched to a host
    uuid that no longer exists — reset + round-robin against live hosts."""
    monkeypatch.setenv("DECNET_MODE", "master")
    for row in await repo.list_swarm_hosts():
        await repo.delete_swarm_host(row["uuid"])

    from datetime import datetime, timezone
    await repo.add_swarm_host({
        "uuid": "host-LIVE",
        "name": "live",
        "address": "10.0.0.60",
        "agent_port": 8765,
        "status": "active",
        "client_cert_fingerprint": "a" * 64,
        "updater_cert_fingerprint": None,
        "cert_bundle_path": "/tmp/live",
        "enrolled_at": datetime.now(timezone.utc),
        "notes": "",
    })

    # Prior state: decky-old is assigned to a now-decommissioned host.
    await repo.set_state("deployment", {
        "config": {
            "mode": "swarm",
            "interface": "eth0",
            "subnet": "192.168.1.0/24",
            "gateway": "192.168.1.1",
            "deckies": [{
                "name": "decky-old",
                "ip": "192.168.1.50",
                "services": ["ssh"],
                "distro": "debian",
                "base_image": "debian:bookworm-slim",
                "hostname": "decky-old",
                "host_uuid": "ghost-uuid",
            }],
        },
        "compose_path": "",
    })

    fake_response = SwarmDeployResponse(results=[
        SwarmHostResult(host_uuid="host-LIVE", host_name="live", ok=True, detail={})
    ])

    with patch(
        "decnet.web.router.fleet.api_deploy_deckies.dispatch_decnet_config",
        new=AsyncMock(return_value=fake_response),
    ) as mock_dispatch:
        ini = "[decky-new]\nservices = ssh\n"
        resp = await client.post(
            "/api/v1/deckies/deploy",
            json={"ini_content": ini},
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    assert resp.status_code == 200, resp.text
    dispatched = mock_dispatch.await_args.args[0]
    # Both the carried-over decky and the new one must point at the live host.
    assert {d.host_uuid for d in dispatched.deckies} == {"host-LIVE"}

    await repo.delete_swarm_host("host-LIVE")
    await repo.set_state("deployment", None)


@pytest.mark.anyio
async def test_deployment_mode_endpoint(client, auth_token, monkeypatch):
    monkeypatch.setenv("DECNET_MODE", "master")
    for row in await repo.list_swarm_hosts():
        await repo.delete_swarm_host(row["uuid"])

    resp = await client.get(
        "/api/v1/system/deployment-mode",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["role"] == "master"
    assert body["mode"] == "unihost"
    assert body["swarm_host_count"] == 0
