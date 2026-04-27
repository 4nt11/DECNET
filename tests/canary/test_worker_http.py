"""HTTP surface coverage for the canary worker.

We exercise the FastAPI app via Starlette's TestClient so the test
doesn't need a real socket. Asserts:

* ``GET /c/{slug}`` for a known slug returns 200 + image/gif, persists
  a trigger row, bumps the token's counters, and publishes
  ``canary.<token_id>.triggered`` on the bus.
* ``GET /c/{slug}`` for an unknown slug returns the same 200 (stealth)
  but persists nothing.
* The Server header is rewritten to a generic value (``nginx``).
* Bare root returns 404.
* X-Forwarded-For is honored.
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from decnet.bus import topics
from decnet.bus.fake import FakeBus
from decnet.canary.worker import _build_app
from decnet.web.db.sqlite.repository import SQLiteRepository
import decnet.web.db.models  # noqa: F401


@pytest_asyncio.fixture
async def repo(tmp_path) -> AsyncIterator[SQLiteRepository]:
    r = SQLiteRepository(str(tmp_path / "w.db"))
    await r.initialize()
    yield r


@pytest_asyncio.fixture
async def bus() -> AsyncIterator[FakeBus]:
    b = FakeBus()
    await b.connect()
    yield b
    await b.close()


@pytest.mark.asyncio
async def test_known_slug_records_trigger_and_publishes(
    repo: SQLiteRepository, bus: FakeBus,
) -> None:
    await repo.create_canary_token({
        "uuid": "tok-w1", "kind": "http", "decky_name": "web1",
        "generator": "env_file", "placement_path": "/x",
        "callback_token": "slug-W1", "secret_seed": "s", "created_by": "u1",
    })
    sub = bus.subscribe("canary.>")
    app = _build_app(repo, bus)
    with TestClient(app) as client:
        resp = client.get("/c/slug-W1", headers={"User-Agent": "curl/8.0"})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("image/gif")
    assert resp.headers.get("server") == "nginx"

    event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)
    assert event.topic == topics.canary("tok-w1", topics.CANARY_TRIGGERED)
    assert event.payload["src_ip"]
    assert event.payload["user_agent"] == "curl/8.0"

    triggers = await repo.list_canary_triggers("tok-w1")
    assert len(triggers) == 1
    assert triggers[0]["request_path"] == "/c/slug-W1"

    tok = await repo.get_canary_token("tok-w1")
    assert tok["trigger_count"] == 1


@pytest.mark.asyncio
async def test_unknown_slug_returns_same_response_but_persists_nothing(
    repo: SQLiteRepository, bus: FakeBus,
) -> None:
    app = _build_app(repo, bus)
    with TestClient(app) as client:
        resp = client.get("/c/unknown-slug")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("image/gif")
    # No tokens, no triggers, no nothing.
    assert await repo.list_canary_tokens() == []


@pytest.mark.asyncio
async def test_root_returns_404(repo: SQLiteRepository, bus: FakeBus) -> None:
    app = _build_app(repo, bus)
    with TestClient(app) as client:
        resp = client.get("/")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_xff_is_honored(repo: SQLiteRepository, bus: FakeBus) -> None:
    await repo.create_canary_token({
        "uuid": "tok-xff", "kind": "http", "decky_name": "web1",
        "generator": "env_file", "placement_path": "/x",
        "callback_token": "slug-xff", "secret_seed": "s", "created_by": "u1",
    })
    app = _build_app(repo, bus)
    with TestClient(app) as client:
        client.get("/c/slug-xff", headers={"X-Forwarded-For": "9.9.9.9, 10.0.0.1"})
    triggers = await repo.list_canary_triggers("tok-xff")
    assert triggers[0]["src_ip"] == "9.9.9.9"


@pytest.mark.asyncio
async def test_no_decnet_strings_in_response(repo: SQLiteRepository, bus: FakeBus) -> None:
    """Stealth posture: nothing in the HTTP surface mentions DECNET."""
    app = _build_app(repo, bus)
    with TestClient(app) as client:
        resp = client.get("/c/anything")
        body = resp.content.lower()
        for v in resp.headers.values():
            assert b"decnet" not in v.lower().encode()
        assert b"decnet" not in body
        # Docs / openapi / redoc are disabled.
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/redoc").status_code == 404
