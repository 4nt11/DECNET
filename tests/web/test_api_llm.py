# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for GET/PUT /api/v1/realism/llm."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

import decnet.realism.llm.config as _cfg_mod


@pytest.fixture(autouse=True)
def _reset_llm_cache():
    """Each test starts with no cached backend."""
    _cfg_mod._cached_backend = None
    yield
    _cfg_mod._cached_backend = None


@pytest.fixture()
def fernet_key(monkeypatch) -> str:
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("DECNET_SECRET_KEY", key)
    return key


# ── GET ───────────────────────────────────────────────────────────────────────


class TestGetLLMConfig:
    @pytest.mark.asyncio
    async def test_returns_defaults_when_no_row(self):
        from decnet.web.router.realism.api_llm import get_llm_config, _hydrated
        import decnet.web.router.realism.api_llm as _mod
        _mod._hydrated = False

        with patch("decnet.web.router.realism.api_llm.repo") as mock_repo:
            mock_repo.get_realism_config = AsyncMock(return_value=None)
            result = await get_llm_config(user={"uuid": "u1", "role": "viewer"})

        assert result["provider"] == "ollama"
        assert result["model"] == "llama3.1"
        assert result["api_key_set"] is False

    @pytest.mark.asyncio
    async def test_returns_stored_config(self):
        from decnet.web.router.realism.api_llm import get_llm_config
        import decnet.web.router.realism.api_llm as _mod
        _mod._hydrated = False

        row_value = json.dumps({
            "provider": "ollama",
            "base_url": "http://10.0.0.1:11434",
            "model": "phi3",
            "timeout": 30.0,
        })
        with patch("decnet.web.router.realism.api_llm.repo") as mock_repo:
            mock_repo.get_realism_config = AsyncMock(
                return_value={"value": row_value}
            )
            result = await get_llm_config(user={"uuid": "u1", "role": "viewer"})

        assert result["provider"] == "ollama"
        assert result["base_url"] == "http://10.0.0.1:11434"
        assert result["model"] == "phi3"
        assert result["api_key_set"] is False

    @pytest.mark.asyncio
    async def test_api_key_set_true_when_ciphertext_present(self):
        from decnet.web.router.realism.api_llm import get_llm_config
        import decnet.web.router.realism.api_llm as _mod
        _mod._hydrated = False

        row_value = json.dumps({
            "provider": "ollama",
            "model": "llama3.1",
            "api_key_ciphertext": "gAAAAABxxx",
        })
        with patch("decnet.web.router.realism.api_llm.repo") as mock_repo:
            mock_repo.get_realism_config = AsyncMock(
                return_value={"value": row_value}
            )
            result = await get_llm_config(user={"uuid": "u1", "role": "viewer"})

        assert result["api_key_set"] is True
        assert "api_key_ciphertext" not in result
        assert "api_key" not in result


# ── PUT ───────────────────────────────────────────────────────────────────────


class TestPutLLMConfig:
    @pytest.mark.asyncio
    async def test_saves_and_applies_config(self):
        from decnet.web.router.realism.api_llm import put_llm_config
        from decnet.realism.llm.impl.ollama import OllamaBackend

        with patch("decnet.web.router.realism.api_llm.repo") as mock_repo:
            mock_repo.get_realism_config = AsyncMock(return_value=None)
            mock_repo.set_realism_config = AsyncMock()

            result = await put_llm_config(
                body={"provider": "ollama", "model": "phi3", "timeout": 45.0},
                user={"uuid": "admin-1", "role": "admin"},
            )

        assert result["provider"] == "ollama"
        assert result["model"] == "phi3"
        assert result["timeout"] == 45.0
        mock_repo.set_realism_config.assert_called_once()
        assert isinstance(_cfg_mod.get_cached_backend(), OllamaBackend)

    @pytest.mark.asyncio
    async def test_merges_partial_update(self):
        from decnet.web.router.realism.api_llm import put_llm_config

        existing = json.dumps({
            "provider": "ollama", "model": "llama3.1",
            "base_url": "http://10.0.0.1:11434",
        })
        with patch("decnet.web.router.realism.api_llm.repo") as mock_repo:
            mock_repo.get_realism_config = AsyncMock(
                return_value={"value": existing}
            )
            mock_repo.set_realism_config = AsyncMock()

            result = await put_llm_config(
                body={"model": "qwen2:7b"},
                user={"uuid": "admin-1", "role": "admin"},
            )

        assert result["model"] == "qwen2:7b"
        assert result["base_url"] == "http://10.0.0.1:11434"

    @pytest.mark.asyncio
    async def test_api_key_encrypted_and_not_returned(self, fernet_key):
        from decnet.web.router.realism.api_llm import put_llm_config
        from decnet.web.db.secrets import decrypt_secret

        captured: dict = {}

        async def _capture_set(key, value):
            captured["value"] = value

        with patch("decnet.web.router.realism.api_llm.repo") as mock_repo:
            mock_repo.get_realism_config = AsyncMock(return_value=None)
            mock_repo.set_realism_config = AsyncMock(side_effect=_capture_set)

            result = await put_llm_config(
                body={"provider": "ollama", "api_key": "sk-secret-key"},
                user={"uuid": "admin-1", "role": "admin"},
            )

        assert result["api_key_set"] is True
        assert "api_key" not in result
        stored = json.loads(captured["value"])
        assert stored["api_key_ciphertext"] != "sk-secret-key"
        assert decrypt_secret(stored["api_key_ciphertext"]) == "sk-secret-key"

    @pytest.mark.asyncio
    async def test_empty_api_key_clears_ciphertext(self):
        from decnet.web.router.realism.api_llm import put_llm_config

        existing = json.dumps({
            "provider": "ollama", "model": "llama3.1",
            "api_key_ciphertext": "gAAAAABxxx",
        })
        captured: dict = {}

        async def _cap(key, value):
            captured["value"] = value

        with patch("decnet.web.router.realism.api_llm.repo") as mock_repo:
            mock_repo.get_realism_config = AsyncMock(
                return_value={"value": existing}
            )
            mock_repo.set_realism_config = AsyncMock(side_effect=_cap)

            result = await put_llm_config(
                body={"api_key": ""},
                user={"uuid": "admin-1", "role": "admin"},
            )

        assert result["api_key_set"] is False
        stored = json.loads(captured["value"])
        assert "api_key_ciphertext" not in stored

    @pytest.mark.asyncio
    async def test_absent_api_key_leaves_existing_ciphertext(self):
        from decnet.web.router.realism.api_llm import put_llm_config

        existing = json.dumps({
            "provider": "ollama", "model": "llama3.1",
            "api_key_ciphertext": "gAAAAABxxx",
        })
        captured: dict = {}

        async def _cap(key, value):
            captured["value"] = value

        with patch("decnet.web.router.realism.api_llm.repo") as mock_repo:
            mock_repo.get_realism_config = AsyncMock(
                return_value={"value": existing}
            )
            mock_repo.set_realism_config = AsyncMock(side_effect=_cap)

            result = await put_llm_config(
                body={"model": "phi3"},
                user={"uuid": "admin-1", "role": "admin"},
            )

        assert result["api_key_set"] is True
        stored = json.loads(captured["value"])
        assert stored["api_key_ciphertext"] == "gAAAAABxxx"

    @pytest.mark.asyncio
    async def test_invalid_provider_returns_400(self):
        from decnet.web.router.realism.api_llm import put_llm_config

        with patch("decnet.web.router.realism.api_llm.repo") as mock_repo:
            mock_repo.get_realism_config = AsyncMock(return_value=None)

            with pytest.raises(HTTPException) as exc_info:
                await put_llm_config(
                    body={"provider": "vllm-someday"},
                    user={"uuid": "admin-1", "role": "admin"},
                )

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_invalid_base_url_returns_400(self):
        from decnet.web.router.realism.api_llm import put_llm_config

        with patch("decnet.web.router.realism.api_llm.repo") as mock_repo:
            mock_repo.get_realism_config = AsyncMock(return_value=None)

            with pytest.raises(HTTPException) as exc_info:
                await put_llm_config(
                    body={"base_url": "ollama://host"},
                    user={"uuid": "admin-1", "role": "admin"},
                )

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_missing_secret_key_returns_500(self, monkeypatch):
        from decnet.web.router.realism.api_llm import put_llm_config
        monkeypatch.delenv("DECNET_SECRET_KEY", raising=False)

        with patch("decnet.web.router.realism.api_llm.repo") as mock_repo:
            mock_repo.get_realism_config = AsyncMock(return_value=None)

            with pytest.raises(HTTPException) as exc_info:
                await put_llm_config(
                    body={"api_key": "sk-whatever"},
                    user={"uuid": "admin-1", "role": "admin"},
                )

        assert exc_info.value.status_code == 500
