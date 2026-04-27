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
from typing import Any

from decnet.realism.llm.base import LLMBackend


def get_llm(*, model: str | None = None, **kwargs: Any) -> LLMBackend:
    """Instantiate the LLM backend selected by environment.

    *model* (when provided) overrides whatever the backend's own default
    is — e.g. for :class:`OllamaBackend` that's ``llama3.1`` unless
    ``DECNET_REALISM_MODEL`` says otherwise.  Lets the worker honour
    ``decnet orchestrate --model gpt-oss`` without each backend having
    to know about CLI flags.
    """
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
