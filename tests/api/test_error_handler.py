"""Tests for the generic Exception handler at decnet/web/api.py.

Mitigation target: threat model F1/I — "Production error handler suppresses
tracebacks and internal details." Verifies that uncaught exceptions return
an opaque 500 with a correlation id in prod, and include debug detail only
when DECNET_DEVELOPER is on.
"""
from __future__ import annotations

import logging
import re
from typing import AsyncGenerator

import httpx
import pytest

from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from decnet.web.api import app
from decnet.web.dependencies import repo


@pytest.fixture
async def client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Override the shared client fixture to NOT re-raise app exceptions.

    The default `httpx.ASGITransport` re-raises any uncaught exception
    from the app — which defeats the whole point of testing our
    generic exception handler. With `raise_app_exceptions=False`, the
    transport instead returns the HTTP response our handler built.
    """
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def _admin_headers(client: httpx.AsyncClient) -> dict[str, str]:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD},
    )
    token = resp.json()["access_token"]
    # Clear must_change_password so the token passes mutation-gated endpoints.
    await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": DECNET_ADMIN_PASSWORD, "new_password": DECNET_ADMIN_PASSWORD},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp2 = await client.post(
        "/api/v1/auth/login",
        json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD},
    )
    return {"Authorization": f"Bearer {resp2.json()['access_token']}"}


def _raise_boom(*_a, **_kw):
    raise RuntimeError("boom")


@pytest.mark.anyio
async def test_unhandled_exception_prod_shape_is_opaque(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prod mode (DECNET_DEVELOPER=False): 500 with opaque body + error_id.
    Must NOT include traceback or exception_type."""
    import decnet.web.api as _api
    monkeypatch.setattr(_api, "DECNET_DEVELOPER", False)

    headers = await _admin_headers(client)
    monkeypatch.setattr(repo, "get_attacker_by_uuid", _raise_boom)

    r = await client.get("/api/v1/attackers/any-uuid", headers=headers)

    assert r.status_code == 500
    body = r.json()
    assert body.get("detail") == "Internal Server Error"
    assert "error_id" in body
    assert re.fullmatch(r"[0-9a-f]{32}", body["error_id"]), body["error_id"]
    assert "traceback" not in body
    assert "exception_type" not in body


@pytest.mark.anyio
async def test_unhandled_exception_dev_shape_includes_traceback(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dev mode (DECNET_DEVELOPER=True): body includes exception_type and
    traceback so failures are debuggable without tailing server logs."""
    import decnet.web.api as _api
    monkeypatch.setattr(_api, "DECNET_DEVELOPER", True)

    headers = await _admin_headers(client)
    monkeypatch.setattr(repo, "get_attacker_by_uuid", _raise_boom)

    r = await client.get("/api/v1/attackers/any-uuid", headers=headers)

    assert r.status_code == 500
    body = r.json()
    assert body["detail"] == "Internal Server Error"
    assert "error_id" in body
    assert body["exception_type"] == "RuntimeError"
    assert "RuntimeError" in body["traceback"]
    assert "boom" in body["traceback"]


@pytest.mark.anyio
async def test_unhandled_exception_logs_error_id(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The same error_id returned to the client must appear in server logs,
    so operators can correlate a user's 500 report with the full traceback."""
    import decnet.web.api as _api
    monkeypatch.setattr(_api, "DECNET_DEVELOPER", False)

    headers = await _admin_headers(client)
    monkeypatch.setattr(repo, "get_attacker_by_uuid", _raise_boom)

    with caplog.at_level(logging.ERROR, logger="api"):
        r = await client.get("/api/v1/attackers/any-uuid", headers=headers)

    assert r.status_code == 500
    error_id = r.json()["error_id"]
    assert any(error_id in rec.getMessage() for rec in caplog.records), (
        f"error_id {error_id} not found in captured logs: "
        f"{[rec.getMessage() for rec in caplog.records]}"
    )
