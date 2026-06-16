# SPDX-License-Identifier: AGPL-3.0-or-later
"""Backend dispatch.

Reads ``DECNET_REALISM_LLM`` to pick a concrete :class:`LLMBackend`.
Defaults to ``ollama`` because that's what the prototype proved out and
what most dev boxes have on hand.

Supported keys:

* ``ollama`` — :class:`decnet.realism.llm.impl.ollama.OllamaBackend`
* ``fake``   — :class:`decnet.realism.llm.impl.fake.FakeBackend`
  (canned output, used by tests so they don't shell out)

Anthropic / vLLM / llama.cpp slots in here as a third branch when the
need shows up.  Per the provider-subpackages convention, do NOT collapse
factory dispatch into the impl modules — keeps the ``__init__`` import
graph cycle-free and the env contract auditable in one place.
"""
from __future__ import annotations

import os
from typing import Any, cast

from decnet.realism.llm.base import LLMBackend


def get_llm(*, model: str | None = None, **kwargs: Any) -> LLMBackend:
    """Instantiate the LLM backend selected by DB config or environment.

    Resolution order:
    1. Process-level cached backend (populated by the DB config row via
       :func:`decnet.realism.llm.config.apply`).  Returned as-is when
       *model* and *kwargs* are both absent — the common case.
    2. Env-var path (``DECNET_REALISM_LLM`` / ``DECNET_REALISM_MODEL`` /
       ``DECNET_REALISM_TIMEOUT``) — legacy / default-install fallback.

    *model* (when provided) overrides whatever the backend's own default
    is — e.g. for :class:`OllamaBackend` that's ``llama3.1`` unless
    ``DECNET_REALISM_MODEL`` says otherwise.  Lets the worker honour
    ``decnet orchestrate --model gpt-oss`` without each backend having
    to know about CLI flags.
    """
    # Fast path: DB-configured cached backend.
    if model is None and not kwargs:
        from decnet.realism.llm.config import get_cached_backend
        cached = get_cached_backend()
        if cached is not None:
            return cast(LLMBackend, cached)

    backend_key = os.environ.get("DECNET_REALISM_LLM", "ollama").lower()

    if backend_key == "ollama":
        from decnet.realism.llm.impl.ollama import OllamaBackend
        return OllamaBackend(model=model, **kwargs)
    if backend_key == "fake":
        from decnet.realism.llm.impl.fake import FakeBackend
        return FakeBackend(model=model or "fake-model", **kwargs)
    raise ValueError(
        f"Unsupported DECNET_REALISM_LLM={backend_key!r}; "
        "expected one of: ollama, fake"
    )
