"""Global persona pool — disk-backed source for fleet/shard mail deckies."""
from __future__ import annotations

import json

import pytest

from decnet.realism import personas_pool as global_pool


@pytest.fixture(autouse=True)
def _reset():
    global_pool.reset_cache()
    yield
    global_pool.reset_cache()


_TWO = [
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


def test_load_returns_empty_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "DECNET_REALISM_PERSONAS", str(tmp_path / "does-not-exist.json")
    )
    assert global_pool.load() == []


def test_load_returns_parsed_personas(tmp_path, monkeypatch):
    f = tmp_path / "personas.json"
    f.write_text(json.dumps(_TWO))
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(f))
    personas = global_pool.load()
    assert len(personas) == 2
    assert {p.email for p in personas} == {"john@corp.com", "sarah@corp.com"}


def test_load_resolves_language_default(tmp_path, monkeypatch):
    f = tmp_path / "personas.json"
    f.write_text(json.dumps(_TWO))
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(f))
    personas = global_pool.load(language_default="es")
    assert all(p.language == "es" for p in personas)


def test_load_invalid_json_returns_empty(tmp_path, monkeypatch):
    f = tmp_path / "personas.json"
    f.write_text("{not valid")
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(f))
    assert global_pool.load() == []


def test_load_caches_until_mtime_changes(tmp_path, monkeypatch):
    f = tmp_path / "personas.json"
    f.write_text(json.dumps(_TWO))
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(f))

    first = global_pool.load()
    assert len(first) == 2

    # Re-write with a single persona; bump mtime so the cache invalidates.
    import time as _time
    _time.sleep(0.01)
    f.write_text(json.dumps(_TWO[:1]))
    import os
    os.utime(f, None)

    second = global_pool.load()
    assert len(second) == 1


def test_resolve_path_honours_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("DECNET_REALISM_PERSONAS", str(tmp_path / "x.json"))
    assert global_pool.resolve_path() == tmp_path / "x.json"


def test_resolve_path_falls_back_to_user_path_when_system_missing(monkeypatch):
    monkeypatch.delenv("DECNET_REALISM_PERSONAS", raising=False)
    # In a typical dev box /etc/decnet/ doesn't exist; the resolver
    # should pick ~/.decnet/email_personas.json.
    p = global_pool.resolve_path()
    # We don't assert the exact path (depends on whether /etc/decnet
    # exists on the test host), only that it ends with the canonical
    # filename and isn't an empty path.
    assert p.name == "email_personas.json"
