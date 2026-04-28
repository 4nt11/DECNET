"""LLM backend for the realism library.

Pluggable per the provider-subpackages convention (mirrors
:mod:`decnet.web.db` and :mod:`decnet.bus`): consumers depend on
:class:`LLMBackend` from :mod:`base`; concrete transports live under
:mod:`impl` and are selected by :func:`get_llm`.

This is the seam to pull on when swapping local Ollama for the
Anthropic API, llama.cpp, vLLM, or any other inference server — change
``DECNET_REALISM_LLM`` (or pass ``llm=`` directly), no caller rewrite.
"""
from __future__ import annotations

from decnet.realism.llm.base import LLMBackend, LLMResult, LLMTimeout
from decnet.realism.llm.factory import get_llm

__all__ = ["LLMBackend", "LLMResult", "LLMTimeout", "get_llm"]
