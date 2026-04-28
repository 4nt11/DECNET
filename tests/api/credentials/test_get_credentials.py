import pytest
import httpx
from hypothesis import given, settings, strategies as st
from ..conftest import _FUZZ_SETTINGS


@pytest.mark.anyio
async def test_get_credentials_empty(client: httpx.AsyncClient, auth_token: str):
    resp = await client.get(
        "/api/v1/credentials",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "data" in data
    assert isinstance(data["data"], list)


@pytest.mark.anyio
async def test_credentials_pagination(client: httpx.AsyncClient, auth_token: str):
    resp = await client.get(
        "/api/v1/credentials?limit=1&offset=0",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["limit"] == 1


@pytest.mark.anyio
async def test_credentials_requires_auth(client: httpx.AsyncClient):
    resp = await client.get("/api/v1/credentials")
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_credentials_filter_passthrough(
    client: httpx.AsyncClient, auth_token: str
):
    # Filter values that match no rows should still 200 with empty data.
    resp = await client.get(
        "/api/v1/credentials",
        params={"service": "ssh", "attacker_ip": "10.0.0.1", "search": "nope"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"] == []


@pytest.mark.fuzz
@pytest.mark.anyio
@settings(**_FUZZ_SETTINGS)
@given(
    limit=st.integers(min_value=-2000, max_value=5000),
    offset=st.integers(min_value=-2000, max_value=5000),
    service=st.one_of(st.none(), st.text(max_size=256)),
    attacker_ip=st.one_of(st.none(), st.text(max_size=64)),
    search=st.one_of(st.none(), st.text(max_size=2048)),
)
async def test_fuzz_credentials_query(
    client: httpx.AsyncClient,
    auth_token: str,
    limit: int,
    offset: int,
    service,
    attacker_ip,
    search,
) -> None:
    params: dict = {"limit": limit, "offset": offset}
    if service is not None:
        params["service"] = service
    if attacker_ip is not None:
        params["attacker_ip"] = attacker_ip
    if search is not None:
        params["search"] = search
    try:
        resp = await client.get(
            "/api/v1/credentials",
            params=params,
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp.status_code in (200, 422)
    except UnicodeEncodeError:
        pass
