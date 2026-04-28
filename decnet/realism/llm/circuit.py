"""Process-local circuit breaker for LLM calls.

Per-call timeouts (``asyncio.wait_for(llm.generate, timeout=...)``)
protect a single tick from a single hung Ollama.  They do NOT protect
the worker from a *sustained* problem: 100 consecutive 60-second
timeouts chew up an hour of orchestrator time on dead requests before
anything notices.

This breaker watches a sliding window of recent outcomes and flips
``open`` after ``failure_threshold`` consecutive failures.  Open
breakers short-circuit ``allow_call`` to ``False`` so callers fall
back to deterministic templates without the per-tick cost.  After
``cooldown_seconds`` the breaker enters ``half_open`` and the next
call is allowed; success closes the breaker, failure re-opens it
with a fresh cooldown.

Process-local on purpose — cross-process state would require shared
memory and is overkill for a single orchestrator worker.
"""
from __future__ import annotations

import threading
import time
from enum import Enum


class _State(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class LLMCircuitBreaker:
    """Threadsafe sliding-window circuit breaker.

    Default ``failure_threshold=3`` consecutive failures → open;
    ``cooldown_seconds=60`` of open before transitioning to
    half-open.  These match the realism worker's tick cadence: 3
    consecutive 60s timeouts = 3 minutes of dead air, which is the
    point at which a deterministic fallback is overdue.
    """

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
        clock=time.monotonic,
    ) -> None:
        self._failure_threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._state = _State.CLOSED
        self._consecutive_failures = 0
        self._opened_at: float = 0.0

    @property
    def state(self) -> str:
        with self._lock:
            return self._state.value

    def allow_call(self) -> bool:
        """Return True if the next call should run, False if it should
        short-circuit to the fallback path.

        Promotes ``open`` → ``half_open`` after the cooldown elapses
        so the next caller acts as a probe.
        """
        with self._lock:
            if self._state == _State.CLOSED:
                return True
            if self._state == _State.HALF_OPEN:
                return True
            # OPEN: check cooldown.
            if self._clock() - self._opened_at >= self._cooldown:
                self._state = _State.HALF_OPEN
                return True
            return False

    def record_success(self) -> None:
        with self._lock:
            self._state = _State.CLOSED
            self._consecutive_failures = 0
            self._opened_at = 0.0

    def record_failure(self) -> None:
        with self._lock:
            if self._state == _State.HALF_OPEN:
                # The probe call failed — re-open with a fresh cooldown.
                self._state = _State.OPEN
                self._opened_at = self._clock()
                # Don't reset the failure count; the probe failure
                # implies the underlying issue is unresolved.
                return
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._failure_threshold:
                self._state = _State.OPEN
                self._opened_at = self._clock()
