# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
import httpx
from ..conftest import _FUZZ_SETTINGS
from hypothesis import given, strategies as st, settings

@pytest.mark.anyio
async def test_get_stats_unauthorized(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/stats")
    assert response.status_code == 401

@pytest.mark.anyio
async def test_get_stats_success(client: httpx.AsyncClient, auth_token: str) -> None:
    response = await client.get(
        "/api/v1/stats",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "total_logs" in data
    assert "unique_attackers" in data
    assert "active_deckies" in data

@pytest.mark.anyio
async def test_stats_includes_deployed_count(mock_state_file, client: httpx.AsyncClient, auth_token: str):
    _response = await client.get("/api/v1/stats", headers={"Authorization": f"Bearer {auth_token}"})
    assert _response.status_code == 200
    _data = _response.json()
    assert "deployed_deckies" in _data
    assert _data["deployed_deckies"] == 2

@pytest.mark.fuzz
@pytest.mark.anyio
@settings(**_FUZZ_SETTINGS)
@given(
    token=st.text(min_size=0, max_size=4096)
)
async def test_fuzz_auth_header(client: httpx.AsyncClient, token: str) -> None:
    """Fuzz the Authorization header with full unicode noise."""
    try:
        _response: httpx.Response = await client.get(
            "/api/v1/stats",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert _response.status_code in (401, 422)
    except (UnicodeEncodeError, httpx.InvalidURL, httpx.CookieConflict):
        # Expected client-side rejection of invalid header characters
        pass
