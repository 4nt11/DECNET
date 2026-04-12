import pytest
import httpx
from hypothesis import given, settings, strategies as st
from ..conftest import _FUZZ_SETTINGS

@pytest.mark.anyio
async def test_add_and_get_bounty(client: httpx.AsyncClient, auth_token: str):
    # We can't directly call add_bounty from API yet (it's internal to ingester)
    # But we can test the endpoint returns 200 even if empty.
    resp = await client.get("/api/v1/bounty", headers={"Authorization": f"Bearer {auth_token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "data" in data
    assert isinstance(data["data"], list)

@pytest.mark.anyio
async def test_bounty_pagination(client: httpx.AsyncClient, auth_token: str):
    resp = await client.get("/api/v1/bounty?limit=1&offset=0", headers={"Authorization": f"Bearer {auth_token}"})
    assert resp.status_code == 200
    assert resp.json()["limit"] == 1

@pytest.mark.fuzz
@pytest.mark.anyio
@settings(**_FUZZ_SETTINGS)
@given(
    limit=st.integers(min_value=-2000, max_value=5000),
    offset=st.integers(min_value=-2000, max_value=5000),
    bounty_type=st.one_of(st.none(), st.text(max_size=256)),
    search=st.one_of(st.none(), st.text(max_size=2048)),
)
async def test_fuzz_bounty_query(client: httpx.AsyncClient, auth_token: str, limit: int, offset: int, bounty_type, search) -> None:
    params = {"limit": limit, "offset": offset}
    if bounty_type is not None:
        params["bounty_type"] = bounty_type
    if search is not None:
        params["search"] = search
    try:
        resp = await client.get("/api/v1/bounty", params=params, headers={"Authorization": f"Bearer {auth_token}"})
        assert resp.status_code in (200, 422)
    except (UnicodeEncodeError,):
        pass
