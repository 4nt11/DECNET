"""GET/PUT /api/v1/emailgen/personas — global persona pool CRUD."""
from __future__ import annotations

import json

import pytest

from decnet.realism import personas_pool as global_pool
from decnet.web.router.emailgen.api_personas import (
    list_personas,
    replace_personas,
)


@pytest.fixture(autouse=True)
def _reset_pool():
    global_pool.reset_cache()
    yield
    global_pool.reset_cache()


_VALID = [
    {
        "name": "John Smith",
        "email": "john@corp.com",
        "role": "COO",
        "tone": "formal",
        "mannerisms": ["uses 'Best regards'"],
    },
    {
        "name": "Sarah Johnson",
        "email": "sarah@corp.com",
        "role": "PM",
        "tone": "direct",
        "mannerisms": ["uses bullets"],
    },
]


@pytest.mark.asyncio
async def test_list_returns_empty_when_no_pool(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "DECNET_REALISM_PERSONAS", str(tmp_path / "missing.json"),
    )
    result = await list_personas(user={"uuid": "u", "role": "viewer"})
    assert result["personas"] == []
    assert result["path"].endswith("missing.json")


@pytest.mark.asyncio
async def test_list_returns_existing_pool(tmp_path, monkeypatch):
    pool = tmp_path / "pool.json"
    pool.write_text(json.dumps(_VALID))
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(pool))

    result = await list_personas(user={"uuid": "u", "role": "viewer"})
    assert len(result["personas"]) == 2
    assert {p["email"] for p in result["personas"]} == {
        "john@corp.com", "sarah@corp.com",
    }


@pytest.mark.asyncio
async def test_replace_writes_canonical_file(tmp_path, monkeypatch):
    dest = tmp_path / "pool.json"
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(dest))

    result = await replace_personas(
        body={"personas": _VALID},
        user={"uuid": "u", "role": "admin", "username": "anti"},
    )
    assert len(result["personas"]) == 2
    assert dest.exists()
    written = json.loads(dest.read_text())
    assert {p["email"] for p in written} == {
        "john@corp.com", "sarah@corp.com",
    }


@pytest.mark.asyncio
async def test_replace_with_empty_list_clears_pool(tmp_path, monkeypatch):
    """Operator deliberately wiping the pool is allowed — empty list is
    valid and means "no fleet personas, skip fleet mail deckies"."""
    dest = tmp_path / "pool.json"
    dest.write_text(json.dumps(_VALID))
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(dest))

    result = await replace_personas(
        body={"personas": []},
        user={"uuid": "u", "role": "admin", "username": "anti"},
    )
    assert result["personas"] == []
    assert json.loads(dest.read_text()) == []


@pytest.mark.asyncio
async def test_replace_rejects_non_list_payload(tmp_path, monkeypatch):
    from fastapi import HTTPException

    monkeypatch.setenv(
        "DECNET_REALISM_PERSONAS", str(tmp_path / "pool.json"),
    )
    with pytest.raises(HTTPException) as exc:
        await replace_personas(
            body={"personas": "not-a-list"},
            user={"uuid": "u", "role": "admin", "username": "anti"},
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_replace_rejects_all_invalid_payload(tmp_path, monkeypatch):
    """Sending a non-empty list where *every* entry is invalid is almost
    certainly an operator schema mistake — fail loudly rather than
    silently writing an empty pool."""
    from fastapi import HTTPException

    monkeypatch.setenv(
        "DECNET_REALISM_PERSONAS", str(tmp_path / "pool.json"),
    )
    with pytest.raises(HTTPException) as exc:
        await replace_personas(
            body={"personas": [{"name": "broken", "email": "no-at-symbol"}]},
            user={"uuid": "u", "role": "admin", "username": "anti"},
        )
    assert exc.value.status_code == 400
    assert "validation" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_replace_drops_partially_invalid_entries(tmp_path, monkeypatch):
    """One bad apple doesn't kill the request — invalid entries get
    dropped, valid ones land, response shows what stuck."""
    dest = tmp_path / "pool.json"
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(dest))

    result = await replace_personas(
        body={"personas": [
            _VALID[0],
            {"name": "broken", "email": "no-at-symbol"},
            _VALID[1],
        ]},
        user={"uuid": "u", "role": "admin", "username": "anti"},
    )
    assert len(result["personas"]) == 2
    assert {p["email"] for p in result["personas"]} == {
        "john@corp.com", "sarah@corp.com",
    }


@pytest.mark.asyncio
async def test_get_then_put_round_trips_through_pool(tmp_path, monkeypatch):
    """The worker reads the same file the API writes — verify the
    write-then-read cycle leaves the pool in the expected state."""
    dest = tmp_path / "pool.json"
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(dest))

    await replace_personas(
        body={"personas": _VALID},
        user={"uuid": "u", "role": "admin", "username": "anti"},
    )
    listed = await list_personas(user={"uuid": "u", "role": "viewer"})
    assert {p["email"] for p in listed["personas"]} == {
        "john@corp.com", "sarah@corp.com",
    }
    # And the worker's loader sees the same data.
    loaded = global_pool.load()
    assert {p.email for p in loaded} == {
        "john@corp.com", "sarah@corp.com",
    }
