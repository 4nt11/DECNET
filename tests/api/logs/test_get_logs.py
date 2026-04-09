from typing import Any, Optional
from fastapi.testclient import TestClient
from decnet.web.api import app
from hypothesis import given, strategies as st, settings
import httpx
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from ..conftest import _FUZZ_SETTINGS

def test_get_logs_unauthorized() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/logs")
        assert response.status_code == 401

def test_get_logs_success() -> None:
    with TestClient(app) as client:
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD}
        )
        token = login_response.json()["access_token"]
        
        response = client.get(
            "/api/v1/logs",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert data["total"] >= 0
        assert isinstance(data["data"], list)

@settings(**_FUZZ_SETTINGS)
@given(
    limit=st.integers(min_value=-2000, max_value=5000),
    offset=st.integers(min_value=-2000, max_value=5000),
    search=st.one_of(st.none(), st.text(max_size=2048))
)
def test_fuzz_get_logs(limit: int, offset: int, search: Optional[str]) -> None:
    with TestClient(app) as _client:
        _login_resp: httpx.Response = _client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
        _token: str = _login_resp.json()["access_token"]
        
        _params: dict[str, Any] = {"limit": limit, "offset": offset}
        if search is not None:
            _params["search"] = search
            
        _response: httpx.Response = _client.get(
            "/api/v1/logs",
            params=_params,
            headers={"Authorization": f"Bearer {_token}"}
        )
        
        assert _response.status_code in (200, 422)
