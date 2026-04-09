import json
from fastapi.testclient import TestClient
from decnet.web.api import app
from hypothesis import given, strategies as st, settings
import httpx
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from ..conftest import _FUZZ_SETTINGS

def test_login_success() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/login", 
            json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "must_change_password" in data
        assert data["must_change_password"] is True

def test_login_failure() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/login", 
            json={"username": DECNET_ADMIN_USER, "password": "wrongpassword"}
        )
        assert response.status_code == 401
        
        response = client.post(
            "/api/v1/auth/login", 
            json={"username": "nonexistent", "password": "wrongpassword"}
        )
        assert response.status_code == 401

@settings(**_FUZZ_SETTINGS)
@given(
    username=st.text(min_size=0, max_size=2048),
    password=st.text(min_size=0, max_size=2048)
)
def test_fuzz_login(username: str, password: str) -> None:
    """Fuzz the login endpoint with random strings (including non-ASCII)."""
    with TestClient(app) as _client:
        _payload: dict[str, str] = {"username": username, "password": password}
        try:
            _response: httpx.Response = _client.post("/api/v1/auth/login", json=_payload)
            assert _response.status_code in (200, 401, 422)
        except (UnicodeEncodeError, json.JSONDecodeError):
            pass
