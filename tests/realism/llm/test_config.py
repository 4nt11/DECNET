"""Tests for decnet.realism.llm.config and the updated factory DB-first path."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from decnet.realism.llm import config as _cfg_mod
from decnet.realism.llm import get_llm
from decnet.realism.llm.impl.fake import FakeBackend
from decnet.realism.llm.impl.ollama import OllamaBackend


# ── LLMConfig validation ──────────────────────────────────────────────────────


def test_defaults():
    c = _cfg_mod.LLMConfig()
    assert c.provider == "ollama"
    assert c.base_url is None
    assert c.model == "llama3.1"
    assert c.timeout == 60.0


def test_base_url_trailing_slash_stripped():
    c = _cfg_mod.LLMConfig(base_url="http://localhost:11434/")
    assert c.base_url == "http://localhost:11434"


def test_base_url_empty_string_normalised_to_none():
    c = _cfg_mod.LLMConfig(base_url="")
    assert c.base_url is None


def test_base_url_non_http_rejected():
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="http"):
        _cfg_mod.LLMConfig(base_url="ollama://localhost")


def test_unknown_provider_rejected():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        _cfg_mod.LLMConfig(provider="vllm")


# ── apply() builds the right backend ─────────────────────────────────────────


def test_apply_ollama_no_url():
    _cfg_mod._cached_backend = None
    _cfg_mod.apply(_cfg_mod.LLMConfig(provider="ollama", model="phi3"))
    b = _cfg_mod.get_cached_backend()
    assert isinstance(b, OllamaBackend)
    assert b.model == "phi3"
    assert b.base_url is None


def test_apply_ollama_with_url():
    _cfg_mod._cached_backend = None
    _cfg_mod.apply(_cfg_mod.LLMConfig(
        provider="ollama",
        model="llama3.1",
        base_url="http://10.0.0.1:11434",
    ))
    b = _cfg_mod.get_cached_backend()
    assert isinstance(b, OllamaBackend)
    assert b.base_url == "http://10.0.0.1:11434"


def test_apply_fake():
    _cfg_mod._cached_backend = None
    _cfg_mod.apply(_cfg_mod.LLMConfig(provider="fake"))
    b = _cfg_mod.get_cached_backend()
    assert isinstance(b, FakeBackend)


def test_apply_ollama_with_api_key(monkeypatch):
    from cryptography.fernet import Fernet
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("DECNET_SECRET_KEY", key)
    from decnet.web.db.secrets import encrypt_secret
    ct = encrypt_secret("sk-supersecret")
    _cfg_mod._cached_backend = None
    _cfg_mod.apply(_cfg_mod.LLMConfig(provider="ollama", api_key_ciphertext=ct))
    b = _cfg_mod.get_cached_backend()
    assert isinstance(b, OllamaBackend)
    assert b.api_key == "sk-supersecret"


# ── load_from_db ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_load_from_db_returns_none_when_no_row():
    repo = MagicMock()
    repo.get_realism_config = AsyncMock(return_value=None)
    result = await _cfg_mod.load_from_db(repo)
    assert result is None


@pytest.mark.asyncio
async def test_load_from_db_parses_valid_row():
    repo = MagicMock()
    payload = {"provider": "ollama", "model": "qwen2:7b", "timeout": 30}
    repo.get_realism_config = AsyncMock(
        return_value={"value": json.dumps(payload)}
    )
    result = await _cfg_mod.load_from_db(repo)
    assert result is not None
    assert result.model == "qwen2:7b"
    assert result.timeout == 30.0


@pytest.mark.asyncio
async def test_load_from_db_returns_none_on_bad_json():
    repo = MagicMock()
    repo.get_realism_config = AsyncMock(return_value={"value": "not-json{{"})
    result = await _cfg_mod.load_from_db(repo)
    assert result is None


@pytest.mark.asyncio
async def test_load_from_db_returns_none_on_db_error():
    repo = MagicMock()
    repo.get_realism_config = AsyncMock(side_effect=RuntimeError("db down"))
    result = await _cfg_mod.load_from_db(repo)
    assert result is None


# ── factory DB-first path ─────────────────────────────────────────────────────


def test_factory_uses_cached_backend_when_set():
    _cfg_mod._cached_backend = None
    _cfg_mod.apply(_cfg_mod.LLMConfig(provider="fake"))
    backend = get_llm()
    assert isinstance(backend, FakeBackend)


def test_factory_falls_back_to_env_when_no_cache(monkeypatch):
    _cfg_mod._cached_backend = None
    monkeypatch.setenv("DECNET_REALISM_LLM", "ollama")
    backend = get_llm()
    assert isinstance(backend, OllamaBackend)


def test_factory_model_override_bypasses_cache():
    _cfg_mod._cached_backend = None
    _cfg_mod.apply(_cfg_mod.LLMConfig(provider="fake"))
    # Explicit model override skips the cache and uses env dispatch.
    monkeypatch = None  # model override makes it fall through to env
    # With model= set, the fast-path is skipped; falls to env default.
    import os
    os.environ.setdefault("DECNET_REALISM_LLM", "ollama")
    backend = get_llm(model="llama3:8b")
    assert isinstance(backend, OllamaBackend)
    assert backend.model == "llama3:8b"
