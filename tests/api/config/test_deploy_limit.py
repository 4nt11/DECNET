import pytest
from unittest.mock import patch

from decnet.web.dependencies import repo


@pytest.fixture(autouse=True)
def contract_test_mode(monkeypatch):
    """Skip actual Docker deployment in tests."""
    monkeypatch.setenv("DECNET_CONTRACT_TEST", "true")


@pytest.fixture(autouse=True)
def mock_network():
    """Mock network detection so deploy doesn't call `ip addr show`."""
    with patch("decnet.web.router.fleet.api_deploy_deckies.get_host_ip", return_value="192.168.1.100"):
        yield


@pytest.mark.anyio
async def test_deploy_respects_limit(client, auth_token, mock_state_file):
    """Deploy should reject if total deckies would exceed limit."""
    await repo.set_state("config_limits", {"deployment_limit": 1})
    await repo.set_state("deployment", mock_state_file)

    ini = """[decky-new]
services = ssh
"""
    resp = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": ini},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # 2 existing + 1 new = 3 > limit of 1
    assert resp.status_code == 409
    assert "limit" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_deploy_within_limit(client, auth_token, mock_state_file):
    """Deploy should succeed when within limit."""
    await repo.set_state("config_limits", {"deployment_limit": 100})
    await repo.set_state("deployment", mock_state_file)

    ini = """[decky-new]
services = ssh
"""
    resp = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": ini},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Should not fail due to limit
    if resp.status_code == 409:
        assert "limit" not in resp.json()["detail"].lower()
    else:
        assert resp.status_code == 200
