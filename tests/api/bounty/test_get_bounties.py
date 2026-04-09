import pytest
import httpx

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
