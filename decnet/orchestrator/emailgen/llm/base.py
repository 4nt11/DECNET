"""Backend protocol shared by every LLM transport.

Deliberately narrow: emailgen needs one async ``generate`` call that
takes a prompt string and returns the model's output text plus enough
metadata for the worker to populate the orchestrator-email payload
(model name, latency, success bit).  Streaming, embeddings, multi-turn
chat — all out of scope here; emailgen only ever does one-shot
single-prompt generations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class LLMTimeout(Exception):
    """Raised when a generation exceeds the backend's wall-clock cap.

    Backends MUST raise this rather than returning silently empty
    output; the driver discriminates timeout from "model produced
    nothing useful" so payloads carry the right ``stage`` value.
    """


@dataclass
class LLMResult:
    """Outcome of one ``generate`` call.

    ``success`` is ``False`` when the backend ran cleanly but produced
    no usable output (e.g. an empty stdout).  Hard failures (subprocess
    crash, network error) raise; soft failures land here so the driver
    can persist + log them as one event.
    """
    success: bool
    text: str
    model: str
    latency_ms: int
    extra: dict[str, Any] = field(default_factory=dict)


class LLMBackend(Protocol):
    """Minimal contract for an emailgen LLM provider."""

    model: str
    timeout: float

    async def generate(self, prompt: str) -> LLMResult: ...
