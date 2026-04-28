"""LLMCircuitBreaker — process-local sliding-window breaker."""
from __future__ import annotations

from decnet.realism.llm.circuit import LLMCircuitBreaker


def test_starts_closed_and_allows_calls() -> None:
    breaker = LLMCircuitBreaker()
    assert breaker.state == "closed"
    assert breaker.allow_call() is True


def test_trips_open_after_threshold_failures() -> None:
    clock_value = [0.0]
    breaker = LLMCircuitBreaker(
        failure_threshold=3, cooldown_seconds=60.0,
        clock=lambda: clock_value[0],
    )
    breaker.record_failure()
    assert breaker.state == "closed"
    breaker.record_failure()
    assert breaker.state == "closed"
    breaker.record_failure()
    assert breaker.state == "open"
    assert breaker.allow_call() is False


def test_success_resets_consecutive_failure_count() -> None:
    breaker = LLMCircuitBreaker(failure_threshold=3)
    breaker.record_failure()
    breaker.record_failure()
    breaker.record_success()
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state == "closed"  # only 2 since the success


def test_half_open_after_cooldown() -> None:
    clock_value = [0.0]
    breaker = LLMCircuitBreaker(
        failure_threshold=2, cooldown_seconds=10.0,
        clock=lambda: clock_value[0],
    )
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state == "open"
    assert breaker.allow_call() is False

    clock_value[0] = 11.0
    assert breaker.allow_call() is True
    assert breaker.state == "half_open"


def test_half_open_failure_re_opens() -> None:
    clock_value = [0.0]
    breaker = LLMCircuitBreaker(
        failure_threshold=2, cooldown_seconds=5.0,
        clock=lambda: clock_value[0],
    )
    breaker.record_failure()
    breaker.record_failure()
    clock_value[0] = 6.0
    breaker.allow_call()
    assert breaker.state == "half_open"
    breaker.record_failure()
    assert breaker.state == "open"


def test_half_open_success_closes() -> None:
    clock_value = [0.0]
    breaker = LLMCircuitBreaker(
        failure_threshold=2, cooldown_seconds=5.0,
        clock=lambda: clock_value[0],
    )
    breaker.record_failure()
    breaker.record_failure()
    clock_value[0] = 6.0
    breaker.allow_call()
    breaker.record_success()
    assert breaker.state == "closed"
    assert breaker.allow_call() is True
