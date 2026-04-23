import json
import pytest
from hypothesis import given, strategies as st, settings
import httpx
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from decnet.web.limiter import limiter as _login_limiter
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
    # Hypothesis runs hundreds of cases within one test; the rate limiter
    # doesn't care it's fuzzing and would 429 after ~10. Clear per-case.
    _login_limiter.reset()
    _payload: dict[str, str] = {"username": username, "password": password}
    try:
        _response: httpx.Response = await client.post("/api/v1/auth/login", json=_payload)
        assert _response.status_code in (200, 401, 422, 429)
    except (UnicodeEncodeError, json.JSONDecodeError):
        pass


# ─── Rate-limit enforcement ─────────────────────────────────────────────────


@pytest.mark.anyio
async def test_login_ip_bucket_trips_after_10_failures(client: httpx.AsyncClient) -> None:
    """10 failed attempts from one IP → 11th returns 429 with Retry-After."""
    for i in range(10):
        r = await client.post(
            "/api/v1/auth/login",
            json={"username": DECNET_ADMIN_USER, "password": f"wrong-{i}"},
        )
        assert r.status_code == 401, f"attempt {i}: got {r.status_code}"
    r = await client.post(
        "/api/v1/auth/login",
        json={"username": DECNET_ADMIN_USER, "password": "still-wrong"},
    )
    assert r.status_code == 429


@pytest.mark.anyio
async def test_login_successful_attempts_count_against_bucket(
    client: httpx.AsyncClient,
) -> None:
    """Successful logins are also counted — bucket does not reset on success.
    10 successes → 11th returns 429 (whether right or wrong password)."""
    for i in range(10):
        r = await client.post(
            "/api/v1/auth/login",
            json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD},
        )
        assert r.status_code == 200, f"attempt {i}: got {r.status_code}"
    r = await client.post(
        "/api/v1/auth/login",
        json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD},
    )
    assert r.status_code == 429


@pytest.mark.anyio
async def test_login_username_key_extracts_from_body() -> None:
    """Per-username bucket key function: valid body → distinct key per
    user. Malformed body → single shared bucket (intentional: garbage
    traffic throttles as one actor)."""
    from decnet.web.limiter import login_username_key

    class _Req:
        def __init__(self, body: bytes) -> None:
            self._body = body

        async def body(self) -> bytes:
            return self._body

    assert await login_username_key(_Req(b'{"username":"alice","password":"x"}')) == "login-user:alice"
    assert await login_username_key(_Req(b'{"username":"bob","password":"y"}')) == "login-user:bob"
    # Malformed or missing username → single bucket
    assert await login_username_key(_Req(b"not json at all")) == "login-user:__unparseable__"
    assert await login_username_key(_Req(b'{"password":"x"}')) == "login-user:__unparseable__"
    assert await login_username_key(_Req(b"")) == "login-user:__unparseable__"


@pytest.mark.anyio
async def test_login_route_has_both_rate_limits() -> None:
    """Contract test: the login handler must import both key functions
    and have been wrapped by slowapi. Guards against someone removing
    one decorator and not noticing."""
    from decnet.web.router.auth import api_login as _login_mod

    assert hasattr(_login_mod, "login_ip_key")
    assert hasattr(_login_mod, "login_username_key")
    # slowapi wraps the handler; unwrapped original lives at __wrapped__.
    assert getattr(_login_mod.login, "__wrapped__", None) is not None
