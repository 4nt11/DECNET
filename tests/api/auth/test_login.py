import json
import pytest
from fastapi.testclient import TestClient
from decnet.web.api import app
from hypothesis import given, strategies as st, settings
import httpx
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from ..conftest import _FUZZ_SETTINGS

@pytest.mark.anyio
async def test_login_success(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "must_change_password" in data
    assert data["must_change_password"] is True

@pytest.mark.anyio
async def test_login_failure(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": DECNET_ADMIN_USER, "password": "wrongpassword"}
    )
    assert response.status_code == 401

    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistent", "password": "wrongpassword"}
    )
    assert response.status_code == 401

@pytest.mark.anyio
@pytest.mark.fuzz
@pytest.mark.anyio
@settings(**_FUZZ_SETTINGS)
@given(
    username=st.text(min_size=0, max_size=2048),
    password=st.text(min_size=0, max_size=2048)
)
async def test_fuzz_login(client: httpx.AsyncClient, username: str, password: str) -> None:
    """Fuzz the login endpoint with random strings (including non-ASCII)."""
    _payload: dict[str, str] = {"username": username, "password": password}
    try:
        _response: httpx.Response = await client.post("/api/v1/auth/login", json=_payload)
        assert _response.status_code in (200, 401, 422)
    except (UnicodeEncodeError, json.JSONDecodeError):
        pass
