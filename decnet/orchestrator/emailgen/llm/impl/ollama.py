"""Ollama subprocess backend.

Shells out to ``ollama run <model>`` with the prompt fed via stdin.
Mirrors what the original prototype at ``DECNET-EMAILs/main.py`` did,
but lifted out of the driver so the rest of emailgen never imports a
specific transport.

Why subprocess and not the Ollama HTTP API:
* No new dependency (``ollama`` Python lib is optional).
* Works on hosts where Ollama is bound to a unix socket, an unusual TCP
  port, or behind a remote-mount layer — `ollama run` resolves all that.
* Same path the operator uses by hand (``ollama run llama3.1``); easier
  to debug discrepancies between worker output and a console session.

Cost: per-call process spawn (~50ms on a warm box).  Acceptable for
emailgen's tick rate (one email every 5 minutes by default).  When that
cost matters, swap to an HTTP-API backend; the seam is in
:mod:`decnet.orchestrator.emailgen.llm.factory`.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Optional

from decnet.logging import get_logger
from decnet.orchestrator.emailgen.llm.base import (
    LLMBackend,
    LLMResult,
    LLMTimeout,
)

log = get_logger("orchestrator.emailgen.llm")

_OLLAMA = "ollama"
_DEFAULT_MODEL = os.environ.get("DECNET_EMAILGEN_MODEL", "llama3.1")
_DEFAULT_TIMEOUT = float(os.environ.get("DECNET_EMAILGEN_TIMEOUT", "60"))


class OllamaBackend(LLMBackend):
    """Concrete :class:`LLMBackend` that shells out to ``ollama run``."""

    def __init__(
        self,
        *,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self.model = model or _DEFAULT_MODEL
        self.timeout = timeout if timeout is not None else _DEFAULT_TIMEOUT

    async def generate(self, prompt: str) -> LLMResult:
        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                _OLLAMA, "run", self.model,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            latency_ms = int((time.monotonic() - t0) * 1000)
            return LLMResult(
                success=False,
                text="",
                model=self.model,
                latency_ms=latency_ms,
                extra={"rc": 127, "stderr": f"argv[0] not found: {exc}"},
            )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(prompt.encode("utf-8")),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError as exc:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            raise LLMTimeout(
                f"ollama run {self.model} exceeded {self.timeout}s"
            ) from exc

        latency_ms = int((time.monotonic() - t0) * 1000)
        rc = proc.returncode if proc.returncode is not None else -1
        text = stdout.decode("utf-8", "replace")
        stderr_s = stderr.decode("utf-8", "replace")
        if rc != 0 or not text.strip():
            log.warning(
                "ollama backend non-zero / empty rc=%d model=%s stderr=%r",
                rc, self.model, stderr_s[:200],
            )
            return LLMResult(
                success=False,
                text=text,
                model=self.model,
                latency_ms=latency_ms,
                extra={"rc": rc, "stderr": stderr_s.strip()[:256]},
            )
        return LLMResult(
            success=True,
            text=text,
            model=self.model,
            latency_ms=latency_ms,
            extra={"rc": rc},
        )
