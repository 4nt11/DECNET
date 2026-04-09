import pytest
import httpx
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD

@pytest.mark.anyio
async def test_get_deckies_endpoint(mock_state_file, client: httpx.AsyncClient, auth_token: str):
    _response = await client.get("/api/v1/deckies", headers={"Authorization": f"Bearer {auth_token}"})
    assert _response.status_code == 200
    _data = _response.json()
    assert len(_data) == 2
    assert _data[0]["name"] == "test-decky-1"
    assert _data[0]["service_config"]["ssh"]["banner"] == "SSH-2.0-OpenSSH_8.9"
