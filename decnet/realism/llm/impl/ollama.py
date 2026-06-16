# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ollama backend — subprocess (local) or HTTP (remote).

**Subprocess mode** (default, ``base_url=None``)
  Shells out to ``ollama run <model>`` with the prompt on stdin.
  Works on any host where Ollama is reachable however it's bound —
  unix socket, unusual TCP port, remote-mount — because ``ollama run``
  resolves all of that transparently.

**HTTP mode** (``base_url`` set, e.g. ``http://10.0.0.1:11434``)
  POSTs to ``{base_url}/api/generate`` via httpx (non-streaming).
  Required when targeting a remote Ollama daemon.  ``api_key`` is sent
  as ``Authorization: Bearer`` when provided (for reverse-proxy setups).
  No shell metacharacters ever reach the network call — base_url is
  validated by :class:`decnet.realism.llm.config.LLMConfig` before storage.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Optional

from decnet.logging import get_logger
from decnet.realism.llm.base import LLMBackend, LLMResult, LLMTimeout

log = get_logger("realism.llm")

_OLLAMA = "ollama"
_DEFAULT_MODEL = os.environ.get("DECNET_REALISM_MODEL", "llama3.1")
_DEFAULT_TIMEOUT = float(os.environ.get("DECNET_REALISM_TIMEOUT", "60"))


class OllamaBackend(LLMBackend):
    """Concrete :class:`LLMBackend` for Ollama — subprocess or HTTP."""

    def __init__(
        self,
        *,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> None:
        self.model = model or _DEFAULT_MODEL
        self.timeout = timeout if timeout is not None else _DEFAULT_TIMEOUT
        self.base_url = base_url or None
        self.api_key = api_key or None

    async def generate(self, prompt: str) -> LLMResult:
        if self.base_url:
            return await self._generate_http(prompt)
        return await self._generate_subprocess(prompt)

    async def _generate_http(self, prompt: str) -> LLMResult:
        import httpx

        url = f"{self.base_url}/api/generate"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {"model": self.model, "prompt": prompt, "stream": False}

        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
        except httpx.TimeoutException as exc:
            raise LLMTimeout(
                f"ollama HTTP {self.model} exceeded {self.timeout}s"
            ) from exc
        except Exception as exc:  # noqa: BLE001
            latency_ms = int((time.monotonic() - t0) * 1000)
            log.warning("ollama HTTP error model=%s exc=%s", self.model, exc)
            return LLMResult(
                success=False,
                text="",
                model=self.model,
                latency_ms=latency_ms,
                extra={"error": str(exc)},
            )

        latency_ms = int((time.monotonic() - t0) * 1000)
        if resp.status_code != 200:
            log.warning(
                "ollama HTTP non-200 model=%s status=%d body=%r",
                self.model, resp.status_code, resp.text[:200],
            )
            return LLMResult(
                success=False,
                text="",
                model=self.model,
                latency_ms=latency_ms,
                extra={"status": resp.status_code, "body": resp.text[:256]},
            )

        try:
            data = resp.json()
            text = data.get("response", "")
        except Exception:
            text = resp.text

        if not text.strip():
            log.warning("ollama HTTP empty response model=%s", self.model)
            return LLMResult(
                success=False,
                text=text,
                model=self.model,
                latency_ms=latency_ms,
                extra={"status": resp.status_code},
            )

        return LLMResult(
            success=True,
            text=text,
            model=self.model,
            latency_ms=latency_ms,
            extra={"status": resp.status_code},
        )

    async def _generate_subprocess(self, prompt: str) -> LLMResult:
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
