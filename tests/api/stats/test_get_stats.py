from typing import Any
from fastapi.testclient import TestClient
from decnet.web.api import app
from hypothesis import given, strategies as st, settings
import httpx
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from ..conftest import _FUZZ_SETTINGS

def test_get_stats_unauthorized() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/stats")
        assert response.status_code == 401

def test_get_stats_success() -> None:
    with TestClient(app) as client:
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD}
        )
        token = login_response.json()["access_token"]
        
        response = client.get(
            "/api/v1/stats",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_logs" in data
        assert "unique_attackers" in data
        assert "active_deckies" in data

def test_stats_includes_deployed_count(mock_state_file):
    with TestClient(app) as _client:
        _login_resp = _client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
        _token = _login_resp.json()["access_token"]
        
        _response = _client.get("/api/v1/stats", headers={"Authorization": f"Bearer {_token}"})
        assert _response.status_code == 200
        _data = _response.json()
        assert "deployed_deckies" in _data
        assert _data["deployed_deckies"] == 2

@settings(**_FUZZ_SETTINGS)
@given(
    token=st.text(min_size=0, max_size=4096)
)
def test_fuzz_auth_header(token: str) -> None:
    """Fuzz the Authorization header with full unicode noise."""
    with TestClient(app) as _client:
        try:
            _response: httpx.Response = _client.get(
                "/api/v1/stats",
                headers={"Authorization": f"Bearer {token}"}
            )
            assert _response.status_code in (401, 422)
        except (UnicodeEncodeError, httpx.InvalidURL, httpx.CookieConflict):
            # Expected client-side rejection of invalid header characters
            pass
