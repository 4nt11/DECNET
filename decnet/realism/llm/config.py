"""DB-backed LLM provider configuration for the realism subsystem.

The module holds a process-level cached backend that callers obtain via
:func:`decnet.realism.llm.factory.get_llm`.  The cache is populated by:

* The API process: :func:`load_from_db` called on first GET, then
  ``apply`` on each successful PUT.
* The orchestrator worker: :func:`load_from_db` called on the same
  periodic tick that refreshes planner weights.

``get_llm()`` falls back to the env-var path when the cache is ``None``
(i.e. the DB row does not exist yet or has never been loaded).
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from decnet.logging import get_logger

log = get_logger("realism.llm.config")

_SUPPORTED_PROVIDERS = {"ollama", "fake"}
_HTTP_RE = re.compile(r"^https?://", re.IGNORECASE)

# Process-level singleton — rebuilt by apply(), read by get_llm().
_cached_backend: Optional[Any] = None

_CONFIG_KEY = "llm"


class LLMConfig(BaseModel):
    """Operator-tunable LLM provider settings stored in ``realism_config``."""

    provider: str = Field(default="ollama")
    base_url: Optional[str] = Field(default=None)
    model: str = Field(default="llama3.1")
    timeout: float = Field(default=60.0, gt=0)
    # Never returned to callers — encrypted Fernet token, write-only.
    api_key_ciphertext: Optional[str] = Field(default=None)

    @field_validator("provider")
    @classmethod
    def _validate_provider(cls, v: str) -> str:
        if v not in _SUPPORTED_PROVIDERS:
            raise ValueError(
                f"provider must be one of {sorted(_SUPPORTED_PROVIDERS)}, got {v!r}"
            )
        return v

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        if not _HTTP_RE.match(v):
            raise ValueError("base_url must start with http:// or https://")
        return v.rstrip("/")


def get_cached_backend() -> Optional[Any]:
    """Return the cached LLMBackend, or ``None`` if not yet hydrated."""
    return _cached_backend


def apply(cfg: LLMConfig) -> None:
    """Build a backend from *cfg* and install it as the process cache.

    Existing circuit-breaker state is NOT reset — don't wipe a tripped
    breaker just because the operator tuned a URL.
    """
    global _cached_backend

    if cfg.provider == "fake":
        from decnet.realism.llm.impl.fake import FakeBackend
        _cached_backend = FakeBackend(model="fake-model")
        log.info("realism.llm.config: applied provider=fake")
        return

    if cfg.provider == "ollama":
        api_key: Optional[str] = None
        if cfg.api_key_ciphertext:
            try:
                from decnet.web.db.secrets import decrypt_secret
                api_key = decrypt_secret(cfg.api_key_ciphertext)
            except RuntimeError as exc:
                log.warning(
                    "realism.llm.config: DECNET_SECRET_KEY unavailable, "
                    "api_key will not be passed to backend: %s", exc,
                )

        from decnet.realism.llm.impl.ollama import OllamaBackend
        _cached_backend = OllamaBackend(
            model=cfg.model,
            timeout=cfg.timeout,
            base_url=cfg.base_url,
            api_key=api_key,
        )
        log.info(
            "realism.llm.config: applied provider=ollama model=%s base_url=%s",
            cfg.model, cfg.base_url or "(subprocess)",
        )
        return

    raise ValueError(f"apply: unsupported provider {cfg.provider!r}")


async def load_from_db(repo: Any) -> Optional[LLMConfig]:
    """Load the ``key='llm'`` RealismConfig row and return a parsed config.

    Returns ``None`` when the row doesn't exist or the JSON is malformed;
    callers fall back to env-var defaults in both cases.
    """
    try:
        row = await repo.get_realism_config(_CONFIG_KEY)
    except Exception as exc:  # noqa: BLE001
        log.warning("realism.llm.config: DB read failed: %s", exc)
        return None
    if row is None:
        return None
    try:
        data = json.loads(row.get("value") or "{}")
        return LLMConfig(**data)
    except Exception as exc:  # noqa: BLE001
        log.warning("realism.llm.config: malformed config row: %s", exc)
        return None
