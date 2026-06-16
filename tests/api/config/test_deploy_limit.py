# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
from unittest.mock import patch

from decnet.config import DeckyConfig
from decnet.web.db.models import LOCAL_HOST_SENTINEL
from decnet.web.dependencies import repo


@pytest.fixture(autouse=True)
def contract_test_mode(monkeypatch):
    """Skip actual Docker deployment in tests."""
    monkeypatch.setenv("DECNET_CONTRACT_TEST", "true")


@pytest.fixture(autouse=True)
def mock_network():
    """Mock network detection so deploy doesn't call `ip addr show`."""
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


async def _seed_fleet(name: str, ip: str) -> None:
    cfg = DeckyConfig(
        name=name, ip=ip, services=["ssh"], distro="debian",
        base_image="debian", hostname=name,
    )
    await repo.upsert_fleet_decky({
        "host_uuid": LOCAL_HOST_SENTINEL,
        "name": name,
        "services": ["ssh"],
        "decky_config": cfg.model_dump(mode="json"),
        "decky_ip": ip,
        "state": "running",
    })


@pytest.fixture(autouse=True)
async def _isolate_fleet():
    await _clear_fleet()
    yield
    await _clear_fleet()


@pytest.mark.anyio
async def test_deploy_respects_limit(client, auth_token):
    """The limit counts the WHOLE resulting fleet — existing (from
    fleet_deckies) plus the submitted INI — not the INI alone. One existing
    decky + one submitted, against a limit of 1, must be rejected."""
    await repo.set_state("config_limits", {"deployment_limit": 1})
    await _seed_fleet("decky-existing", "192.168.1.10")

    ini = "[decky-new]\nservices = ssh\n"
    resp = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": ini},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # existing(1) + new(1) = 2 > limit 1
    assert resp.status_code == 409
    assert "limit" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_deploy_replaces_prior_state(client, auth_token):
    """replace_fleet=True drops the prior fleet rather than silently
    re-including it (the 'Address already in use' regression came from stale
    deckies redeploying on stale IPs). After replace, the committed fleet is
    exactly the submitted INI."""
    await repo.set_state("config_limits", {"deployment_limit": 10})
    await _seed_fleet("test-decky-1", "192.168.1.10")
    await _seed_fleet("test-decky-2", "192.168.1.11")

    ini = "[only-decky]\nservices = ssh\n"
    resp = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": ini, "replace_fleet": True},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 202, resp.text
    names = {d["name"] for d in await repo.get_deckies()}
    assert names == {"only-decky"}


@pytest.mark.anyio
async def test_deploy_within_limit(client, auth_token):
    """Deploy should succeed when the resulting fleet is within limit."""
    await repo.set_state("config_limits", {"deployment_limit": 100})
    await _seed_fleet("decky-existing", "192.168.1.10")

    ini = "[decky-new]\nservices = ssh\n"
    resp = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": ini},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    if resp.status_code == 409:
        assert "limit" not in resp.json()["detail"].lower()
    else:
        assert resp.status_code == 202
