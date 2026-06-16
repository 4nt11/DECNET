# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET/PUT ``/api/v1/realism/llm`` — LLM provider configuration.

Reads accept viewer; writes are admin (same trust level as the existing
``/realism/config`` surface — LLM provider config controls all AI-generated
honeypot content).

GET returns the current config **without** the encrypted API key — only
``api_key_set: bool`` is surfaced so the operator can see whether one is
stored without ever exfiltrating it.

PUT body fields (all optional — unset fields keep their current value):

* ``provider``:  ``"ollama"`` (only supported provider today)
* ``base_url``:  Ollama daemon URL, or ``""``/``null`` to clear
* ``model``:     Ollama model tag
* ``timeout``:   Generation timeout in seconds (float, > 0)
* ``api_key``:   Plaintext; ``null`` / absent = leave unchanged, ``""`` = clear
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.logging import get_logger
from decnet.realism.llm import config as llm_config
from decnet.realism.llm.config import LLMConfig, _CONFIG_KEY
from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_admin, require_viewer

router = APIRouter()
log = get_logger("api.realism.llm")

_hydrated = False
_hydrate_lock = asyncio.Lock()

_SENTINEL = object()


def _cfg_to_response(cfg: LLMConfig, api_key_set: bool) -> dict[str, Any]:
    return {
        "provider": cfg.provider,
        "base_url": cfg.base_url,
        "model": cfg.model,
        "timeout": cfg.timeout,
        "api_key_set": api_key_set,
    }


async def _load_and_apply_from_db() -> LLMConfig:
    """Load DB row into process cache; return current effective config."""
    cfg = await llm_config.load_from_db(repo)
    if cfg is not None:
        try:
            llm_config.apply(cfg)
        except Exception as exc:  # noqa: BLE001
            log.warning("api.realism.llm: apply on hydrate failed: %s", exc)
    return cfg or LLMConfig()


@router.get(
    "/realism/llm",
    tags=["Realism"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.realism.get_llm")
async def get_llm_config(
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Return the live LLM provider config (API key masked as ``api_key_set``)."""
    global _hydrated
    if not _hydrated:
        async with _hydrate_lock:
            if not _hydrated:
                await _load_and_apply_from_db()
                _hydrated = True

    row = await repo.get_realism_config(_CONFIG_KEY)
    if row is not None:
        try:
            stored: dict[str, Any] = json.loads(row.get("value") or "{}")
        except json.JSONDecodeError:
            stored = {}
    else:
        stored = {}

    cfg = LLMConfig(**stored) if stored else LLMConfig()
    api_key_set = bool(stored.get("api_key_ciphertext"))
    return _cfg_to_response(cfg, api_key_set)


@router.put(
    "/realism/llm",
    tags=["Realism"],
    responses={
        400: {"description": "Invalid config payload"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.realism.put_llm")
async def put_llm_config(
    body: dict[str, Any],
    user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Replace LLM provider config.  Persists and hot-reloads the backend.

    ``api_key`` handling:

    * absent or not in body → leave existing encrypted key unchanged
    * ``null`` or ``""``    → clear the stored key
    * non-empty string      → encrypt and store
    """
    global _hydrated

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="body must be an object")

    # Load the current persisted config so we can merge partial updates.
    row = await repo.get_realism_config(_CONFIG_KEY)
    current: dict[str, Any] = {}
    if row is not None:
        try:
            current = json.loads(row.get("value") or "{}") or {}
        except json.JSONDecodeError:
            current = {}

    api_key_raw: Any = body.pop("api_key", _SENTINEL)

    # Merge incoming fields over the current persisted state.
    merged = {**current, **body}

    # Handle api_key: absent=keep, null/empty=clear, string=encrypt.
    if api_key_raw is _SENTINEL:
        pass  # leave current api_key_ciphertext in merged unchanged
    elif not api_key_raw:
        merged.pop("api_key_ciphertext", None)
    else:
        try:
            from decnet.web.db.secrets import encrypt_secret
            merged["api_key_ciphertext"] = encrypt_secret(str(api_key_raw))
        except RuntimeError:
            log.exception("api.realism.put_llm: secret encryption unavailable")
            raise HTTPException(
                status_code=500,
                detail="Secret encryption unavailable; check server configuration.",
            ) from None

    try:
        cfg = LLMConfig(**merged)
    except Exception as exc:
        log.warning("api.realism.put_llm: LLMConfig validation failed: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid LLM configuration payload.") from exc

    try:
        llm_config.apply(cfg)
    except Exception:
        log.exception("api.realism.put_llm: backend init failed")
        raise HTTPException(
            status_code=400, detail="Backend init failed; check provider/model settings."
        ) from None

    await repo.set_realism_config(_CONFIG_KEY, json.dumps(merged))
    _hydrated = True

    log.info(
        "api.realism.put_llm user=%s provider=%s model=%s base_url=%s",
        user.get("username", user.get("uuid")),
        cfg.provider, cfg.model, cfg.base_url,
    )
    return _cfg_to_response(cfg, bool(merged.get("api_key_ciphertext")))
