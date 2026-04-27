"""LLM status surfaces in the orchestrator's heartbeat ``extra``.

Exposes the realism subsystem's LLM backend / model / circuit-breaker
state so the dashboard can render a status badge without poking
worker process memory.

Pinned by `feedback_push_principled_answer.md`: heartbeat is the
canonical worker self-report channel, so this rides the existing
``run_health_heartbeat(extra=...)`` extension hook rather than carving
a new bus topic.
"""
from __future__ import annotations

from decnet.orchestrator.worker import _realism_health_snapshot
from decnet.realism.llm.circuit import LLMCircuitBreaker


class _FakeLLM:
    model = "llama3.1:8b"


def test_snapshot_reports_disabled_when_no_llm():
    snap = _realism_health_snapshot(llm=None, breaker=None)
    assert snap == {
        "llm_enabled": False,
        "llm_backend": None,
        "llm_model": None,
        "llm_breaker_state": None,
    }


def test_snapshot_carries_backend_model_breaker_state(monkeypatch):
    monkeypatch.setenv("DECNET_REALISM_LLM", "ollama")
    breaker = LLMCircuitBreaker(failure_threshold=2, cooldown_seconds=1.0)
    snap = _realism_health_snapshot(llm=_FakeLLM(), breaker=breaker)
    assert snap["llm_enabled"] is True
    assert snap["llm_backend"] == "ollama"
    assert snap["llm_model"] == "llama3.1:8b"
    assert snap["llm_breaker_state"] == "closed"


def test_snapshot_reflects_open_breaker(monkeypatch):
    monkeypatch.setenv("DECNET_REALISM_LLM", "ollama")
    breaker = LLMCircuitBreaker(failure_threshold=2, cooldown_seconds=60.0)
    breaker.record_failure()
    breaker.record_failure()
    snap = _realism_health_snapshot(llm=_FakeLLM(), breaker=breaker)
    assert snap["llm_breaker_state"] == "open"


def test_snapshot_handles_llm_without_breaker(monkeypatch):
    """Defensive: if init left ``breaker=None`` for any reason, the
    snapshot still publishes — just without breaker state."""
    monkeypatch.setenv("DECNET_REALISM_LLM", "fake")
    snap = _realism_health_snapshot(llm=_FakeLLM(), breaker=None)
    assert snap["llm_enabled"] is True
    assert snap["llm_backend"] == "fake"
    assert snap["llm_breaker_state"] is None
