# SPDX-License-Identifier: AGPL-3.0-or-later
"""In-process fake backend for tests.

Returns a canned string so the driver path can be exercised without an
Ollama install.  Configurable via ``DECNET_REALISM_FAKE_OUTPUT`` (env)
or the ``output`` constructor arg — the env-var path lets integration
tests run the worker end-to-end with deterministic output.
"""
from __future__ import annotations

import os
import time
from typing import Optional

from decnet.realism.llm.base import LLMBackend, LLMResult


_DEFAULT_OUTPUT = (
    "Subject: Quick update\n\n"
    "Hi,\n\nFollowing up on the topic.\n\nBest regards,\nFake Persona\n"
)


class FakeBackend(LLMBackend):
    def __init__(
        self,
        *,
        model: str = "fake-model",
        timeout: float = 1.0,
        output: Optional[str] = None,
        success: bool = True,
    ) -> None:
        self.model = model
        self.timeout = timeout
        self._output = (
            output
            if output is not None
            else os.environ.get("DECNET_REALISM_FAKE_OUTPUT", _DEFAULT_OUTPUT)
        )
        self._success = success

    async def generate(self, _prompt: str) -> LLMResult:
        t0 = time.monotonic()
        latency_ms = int((time.monotonic() - t0) * 1000)
        return LLMResult(
            success=self._success,
            text=self._output if self._success else "",
            model=self.model,
            latency_ms=latency_ms,
            extra={"rc": 0 if self._success else 1},
        )
