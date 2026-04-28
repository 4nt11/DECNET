"""LLM-enriched body generation with deterministic fallback."""
from __future__ import annotations

import asyncio

import pytest

from decnet.realism.bodies import make_body_with_llm
from decnet.realism.llm.base import LLMResult, LLMTimeout
from decnet.realism.llm.circuit import LLMCircuitBreaker
from decnet.realism.personas import EmailPersona
from decnet.realism.taxonomy import ContentClass


def _persona(uses_llms: bool = False) -> EmailPersona:
    return EmailPersona(
        name="admin", email="admin@corp.com", role="ops",
        tone="direct", mannerisms=["uses bullets"],
        active_hours="00:00-00:00",
        uses_llms_heavily=uses_llms,
    )


class _StubLLM:
    """Async stub: returns canned LLMResult; no subprocess work."""

    def __init__(self, *, text: str = "stub body\n", success: bool = True):
        self.model = "stub-model"
        self.timeout = 1.0
        self._result = LLMResult(
            success=success, text=text, model=self.model, latency_ms=1,
        )
        self.calls = 0

    async def generate(self, prompt: str) -> LLMResult:
        self.calls += 1
        return self._result


class _TimeoutLLM:
    model = "timeout-model"
    timeout = 0.05

    async def generate(self, prompt: str) -> LLMResult:
        raise LLMTimeout("simulated")


@pytest.mark.asyncio
async def test_no_llm_falls_back_to_template() -> None:
    body = await make_body_with_llm(ContentClass.NOTE, _persona(), llm=None)
    assert body.strip()  # template path returns non-empty


@pytest.mark.asyncio
async def test_llm_success_returns_llm_text() -> None:
    llm = _StubLLM(text="LLM-produced note body\n")
    body = await make_body_with_llm(
        ContentClass.NOTE, _persona(), llm=llm,
    )
    assert "LLM-produced note body" in body
    assert llm.calls == 1


@pytest.mark.asyncio
async def test_em_dashes_are_stripped_for_default_persona() -> None:
    llm = _StubLLM(text="Hi — quick update — see attached.\n")
    body = await make_body_with_llm(
        ContentClass.NOTE, _persona(uses_llms=False), llm=llm,
    )
    assert "—" not in body


@pytest.mark.asyncio
async def test_em_dashes_pass_through_for_llm_heavy_persona() -> None:
    llm = _StubLLM(text="Hi — quick update — see attached.\n")
    body = await make_body_with_llm(
        ContentClass.NOTE, _persona(uses_llms=True), llm=llm,
    )
    assert "—" in body


@pytest.mark.asyncio
async def test_timeout_falls_back_to_template_and_records_failure() -> None:
    breaker = LLMCircuitBreaker(failure_threshold=3, cooldown_seconds=10.0)
    body = await make_body_with_llm(
        ContentClass.NOTE, _persona(),
        llm=_TimeoutLLM(), breaker=breaker, timeout=0.01,
    )
    assert body.strip()  # template fallback returned non-empty
    assert breaker.state == "closed"  # one failure isn't enough to trip


@pytest.mark.asyncio
async def test_breaker_open_skips_llm_call() -> None:
    breaker = LLMCircuitBreaker(failure_threshold=1, cooldown_seconds=60.0)
    breaker.record_failure()  # trip immediately
    assert breaker.allow_call() is False

    llm = _StubLLM()
    body = await make_body_with_llm(
        ContentClass.NOTE, _persona(),
        llm=llm, breaker=breaker,
    )
    # LLM was NOT called (breaker open) — fallback to template.
    assert llm.calls == 0
    assert body.strip()


@pytest.mark.asyncio
async def test_system_class_never_invokes_llm() -> None:
    llm = _StubLLM()
    body = await make_body_with_llm(
        ContentClass.LOG_CRON, _persona(), llm=llm,
    )
    # System-class content is supposed to look formulaic; LLM-authored
    # cron logs would be a regression in realism.
    assert llm.calls == 0
    assert "CRON[" in body  # template path


@pytest.mark.asyncio
async def test_empty_llm_response_falls_back() -> None:
    llm = _StubLLM(text="", success=True)
    body = await make_body_with_llm(
        ContentClass.NOTE, _persona(), llm=llm,
    )
    # LLM ran but produced empty output → template fallback.
    assert body.strip()
