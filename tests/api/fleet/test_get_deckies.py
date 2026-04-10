import pytest
import httpx
from hypothesis import given, settings, strategies as st
from ..conftest import _FUZZ_SETTINGS

@pytest.mark.anyio
async def test_get_deckies_endpoint(mock_state_file, client: httpx.AsyncClient, auth_token: str):
    _response = await client.get("/api/v1/deckies", headers={"Authorization": f"Bearer {auth_token}"})
    assert _response.status_code == 200
    _data = _response.json()
    assert len(_data) == 2
    assert _data[0]["name"] == "test-decky-1"
    assert _data[0]["service_config"]["ssh"]["banner"] == "SSH-2.0-OpenSSH_8.9"

@pytest.mark.fuzz
@pytest.mark.anyio
@settings(**_FUZZ_SETTINGS)
@given(token=st.text(min_size=0, max_size=4096))
async def test_fuzz_deckies_auth(client: httpx.AsyncClient, token: str) -> None:
    """Fuzz the Authorization header on the deckies endpoint."""
    try:
        resp = await client.get("/api/v1/deckies", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code in (200, 401, 422)
    except (UnicodeEncodeError,):
        pass
