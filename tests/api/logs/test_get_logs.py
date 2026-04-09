import pytest
import httpx
from typing import Any, Optional
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from ..conftest import _FUZZ_SETTINGS
from hypothesis import given, strategies as st, settings

@pytest.mark.anyio
async def test_get_logs_unauthorized(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/logs")
    assert response.status_code == 401

@pytest.mark.anyio
async def test_get_logs_success(client: httpx.AsyncClient, auth_token: str) -> None:
    response = await client.get(
        "/api/v1/logs",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert data["total"] >= 0
    assert isinstance(data["data"], list)

@pytest.mark.fuzz
@pytest.mark.anyio
@settings(**_FUZZ_SETTINGS)
@given(
    limit=st.integers(min_value=-2000, max_value=5000),
    offset=st.integers(min_value=-2000, max_value=5000),
    search=st.one_of(st.none(), st.text(max_size=2048))
)
async def test_fuzz_get_logs(client: httpx.AsyncClient, auth_token: str, limit: int, offset: int, search: Optional[str]) -> None:
    _params: dict[str, Any] = {"limit": limit, "offset": offset}
    if search is not None:
        _params["search"] = search
        
    _response: httpx.Response = await client.get(
        "/api/v1/logs",
        params=_params,
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    
    assert _response.status_code in (200, 422)
