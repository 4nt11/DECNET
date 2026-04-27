"""LLM backend for emailgen.

Pluggable from day one (per the provider-subpackages convention used by
:mod:`decnet.web.db` and :mod:`decnet.bus`): the worker only depends on
:class:`LLMBackend` from :mod:`base`; concrete transports live under
:mod:`impl` and are selected by :func:`get_llm`.

This is the seam ANTI will pull on when swapping local Ollama for the
Anthropic API, llama.cpp, vLLM, or any other inference server — change
``DECNET_EMAILGEN_LLM`` (or pass ``llm=`` to the driver), no driver
rewrite.
"""
from __future__ import annotations

from decnet.orchestrator.emailgen.llm.base import (
    LLMBackend,
    LLMResult,
    LLMTimeout,
)
from decnet.orchestrator.emailgen.llm.factory import get_llm

__all__ = ["LLMBackend", "LLMResult", "LLMTimeout", "get_llm"]
