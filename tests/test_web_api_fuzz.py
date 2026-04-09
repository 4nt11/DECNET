import os
import pytest
import json
from typing import Generator, Any, Optional
from fastapi.testclient import TestClient
from hypothesis import given, strategies as st, settings, HealthCheck
import httpx

from decnet.web.api import app
from decnet.web.dependencies import repo
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD

# Re-use setup from test_web_api
@pytest.fixture(scope="function", autouse=True)
def setup_db() -> Generator[None, None, None]:
    repo.db_path = "test_fuzz_decnet.db"
    if os.path.exists(repo.db_path):
        os.remove(repo.db_path)
    
    repo.reinitialize()
    yield
    if os.path.exists(repo.db_path):
        os.remove(repo.db_path)

# bcrypt is intentionally slow, so we disable/extend the deadline
_FUZZ_SETTINGS: dict[str, Any] = {
    "max_examples": 50,
    "deadline": None, # bcrypt hashing takes >200ms
    "suppress_health_check": [HealthCheck.function_scoped_fixture]
}

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
            # 200, 401, or 422 are acceptable. 500 is a failure.
            assert _response.status_code in (200, 401, 422)
        except (UnicodeEncodeError, json.JSONDecodeError):
            pass

@settings(**_FUZZ_SETTINGS)
@given(
    old_password=st.text(min_size=0, max_size=2048),
    new_password=st.text(min_size=0, max_size=2048)
)
def test_fuzz_change_password(old_password: str, new_password: str) -> None:
    """Fuzz the change-password endpoint with random strings."""
    with TestClient(app) as _client:
        # Get valid token first
        _login_resp: httpx.Response = _client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
        _token: str = _login_resp.json()["access_token"]
        
        _payload: dict[str, str] = {"old_password": old_password, "new_password": new_password}
        try:
            _response: httpx.Response = _client.post(
                "/api/v1/auth/change-password",
                json=_payload,
                headers={"Authorization": f"Bearer {_token}"}
            )
            assert _response.status_code in (200, 401, 422)
        except (UnicodeEncodeError, json.JSONDecodeError):
            pass

@settings(**_FUZZ_SETTINGS)
@given(
    limit=st.integers(min_value=-2000, max_value=5000),
    offset=st.integers(min_value=-2000, max_value=5000),
    search=st.one_of(st.none(), st.text(max_size=2048))
)
def test_fuzz_get_logs(limit: int, offset: int, search: Optional[str]) -> None:
    """Fuzz the logs pagination and search."""
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
