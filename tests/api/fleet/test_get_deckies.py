from fastapi.testclient import TestClient
from decnet.web.api import app
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD

def test_get_deckies_endpoint(mock_state_file):
    with TestClient(app) as _client:
        # Login to get token
        _login_resp = _client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
        _token = _login_resp.json()["access_token"]
        
        _response = _client.get("/api/v1/deckies", headers={"Authorization": f"Bearer {_token}"})
        assert _response.status_code == 200
        _data = _response.json()
        assert len(_data) == 2
        assert _data[0]["name"] == "test-decky-1"
        assert _data[0]["service_config"]["ssh"]["banner"] == "SSH-2.0-OpenSSH_8.9"
