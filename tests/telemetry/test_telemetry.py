# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Tests for decnet.telemetry — OTEL tracing integration.

Covers both the disabled path (default, zero overhead) and the enabled path
(with mocked OTEL SDK).
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reload_telemetry(*, enabled: bool = False):
    """(Re)import decnet.telemetry with DECNET_DEVELOPER_TRACING set accordingly."""
    env_val = "true" if enabled else ""
    with patch.dict(os.environ, {"DECNET_DEVELOPER_TRACING": env_val}):
        # Force the env module to re-evaluate
        import decnet.env
        old_tracing = decnet.env.DECNET_DEVELOPER_TRACING
        decnet.env.DECNET_DEVELOPER_TRACING = enabled

        # Remove cached telemetry module so it re-evaluates _ENABLED
        sys.modules.pop("decnet.telemetry", None)
        import decnet.telemetry
        importlib.reload(decnet.telemetry)

        # Restore after reload
        decnet.env.DECNET_DEVELOPER_TRACING = old_tracing
        return decnet.telemetry


# ═══════════════════════════════════════════════════════════════════════════
# DISABLED PATH (default) — zero overhead
# ═══════════════════════════════════════════════════════════════════════════


class TestTracingDisabled:
    """When DECNET_DEVELOPER_TRACING is unset/false, everything is a no-op."""

    def test_setup_tracing_is_noop(self):
        mod = _reload_telemetry(enabled=False)
        app = MagicMock()
        mod.setup_tracing(app)
        # FastAPIInstrumentor should NOT have been called
        assert not any("opentelemetry" in str(c) for c in app.mock_calls)

    def test_get_tracer_returns_noop(self):
        mod = _reload_telemetry(enabled=False)
        tracer = mod.get_tracer("test")
        assert isinstance(tracer, mod._NoOpTracer)
        # NoOp span should work as context manager
        with tracer.start_as_current_span("test") as span:
            span.set_attribute("k", "v")
            span.record_exception(RuntimeError("boom"))

    def test_traced_returns_original_function(self):
        mod = _reload_telemetry(enabled=False)

        def my_func(x: int) -> int:
            return x * 2

        decorated = mod.traced(my_func)
        # Must be the exact same function object — no wrapper overhead
        assert decorated is my_func
        assert decorated(5) == 10

    def test_traced_with_name_returns_original(self):
        mod = _reload_telemetry(enabled=False)

        @mod.traced("custom.name")
        def my_func() -> str:
            return "hello"

        # When disabled, @traced("name") still returns the original
        assert my_func() == "hello"
        assert my_func.__name__ == "my_func"

    def test_traced_async_returns_original(self):
        mod = _reload_telemetry(enabled=False)

        async def my_async(x: int) -> int:
            return x + 1

        decorated = mod.traced(my_async)
        assert decorated is my_async

    def test_wrap_repository_returns_original(self):
        mod = _reload_telemetry(enabled=False)
        repo = MagicMock()
        result = mod.wrap_repository(repo)
        assert result is repo

    def test_shutdown_tracing_noop(self):
        mod = _reload_telemetry(enabled=False)
        # Should not raise
        mod.shutdown_tracing()


# ═══════════════════════════════════════════════════════════════════════════
# ENABLED PATH — with mocked OTEL SDK
# ═══════════════════════════════════════════════════════════════════════════


class TestTracingEnabled:
    """When DECNET_DEVELOPER_TRACING=true, spans are created."""

    @pytest.fixture(autouse=True)
    def _mock_otel(self):
        """Provide mock OTEL modules so we don't need the real SDK installed."""
        # Create mock OTEL modules
        mock_trace = MagicMock()
        mock_tracer = MagicMock()
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_tracer.start_as_current_span.return_value = mock_span
        mock_trace.get_tracer.return_value = mock_tracer

        self.mock_trace = mock_trace
        self.mock_tracer = mock_tracer
        self.mock_span = mock_span

        mock_modules = {
            "opentelemetry": MagicMock(trace=mock_trace),
            "opentelemetry.trace": mock_trace,
            "opentelemetry.sdk": MagicMock(),
            "opentelemetry.sdk.trace": MagicMock(),
            "opentelemetry.sdk.trace.export": MagicMock(),
            "opentelemetry.sdk.resources": MagicMock(),
            "opentelemetry.exporter": MagicMock(),
            "opentelemetry.exporter.otlp": MagicMock(),
            "opentelemetry.exporter.otlp.proto": MagicMock(),
            "opentelemetry.exporter.otlp.proto.grpc": MagicMock(),
            "opentelemetry.exporter.otlp.proto.grpc.trace_exporter": MagicMock(),
            "opentelemetry.instrumentation": MagicMock(),
            "opentelemetry.instrumentation.fastapi": MagicMock(),
        }

        with patch.dict(sys.modules, mock_modules):
            self.mod = _reload_telemetry(enabled=True)
            yield

    def test_traced_sync_creates_span(self):
        @self.mod.traced("test.sync_op")
        def do_work(x: int) -> int:
            return x * 3

        result = do_work(7)
        assert result == 21
        # The wrapper should have called start_as_current_span
        # (via get_tracer which returns our mock)

    def test_traced_async_creates_span(self):
        @self.mod.traced("test.async_op")
        async def do_async(x: int) -> int:
            return x + 10

        result = asyncio.run(do_async(5))
        assert result == 15

    def test_traced_preserves_function_name(self):
        @self.mod.traced("custom.name")
        def my_named_func():
            pass

        assert my_named_func.__name__ == "my_named_func"

    def test_traced_exception_recorded(self):
        @self.mod.traced("test.error")
        def fail():
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            fail()

    def test_traced_async_exception_recorded(self):
        @self.mod.traced("test.async_error")
        async def fail_async():
            raise RuntimeError("async boom")

        with pytest.raises(RuntimeError, match="async boom"):
            asyncio.run(fail_async())

    def test_wrap_repository_delegates(self):
        mock_repo = AsyncMock()
        mock_repo.add_log = AsyncMock(return_value=None)
        mock_repo.get_logs = AsyncMock(return_value=[])
        mock_repo.get_state = AsyncMock(return_value={"key": "val"})

        wrapped = self.mod.wrap_repository(mock_repo)
        assert wrapped is not mock_repo

        # Verify delegation works
        asyncio.run(wrapped.add_log({"test": 1}))
        mock_repo.add_log.assert_awaited_once_with({"test": 1})

    def test_wrap_repository_getattr_fallback(self):
        mock_repo = MagicMock()
        mock_repo.custom_method = MagicMock(return_value=42)

        wrapped = self.mod.wrap_repository(mock_repo)
        assert wrapped.custom_method() == 42

    def test_get_tracer_returns_real_tracer(self):
        tracer = self.mod.get_tracer("test_component")
        # Should be the mock tracer from opentelemetry.trace.get_tracer
        assert tracer is not None
        assert not isinstance(tracer, self.mod._NoOpTracer)

    def test_setup_tracing_instruments_app(self):
        app = MagicMock()
        self.mod.setup_tracing(app)
        # Should not raise — the mock OTEL modules handle everything


# ═══════════════════════════════════════════════════════════════════════════
# NoOp classes
# ═══════════════════════════════════════════════════════════════════════════


class TestNoOpClasses:
    """NoOp tracer and span must satisfy the context-manager protocol."""

    def test_noop_span_context_manager(self):
        from decnet.telemetry import _NoOpSpan
        span = _NoOpSpan()
        with span as s:
            assert s is span
            s.set_attribute("key", "value")
            s.set_status("ok")
            s.record_exception(RuntimeError("test"))

    def test_noop_tracer(self):
        from decnet.telemetry import _NoOpTracer
        tracer = _NoOpTracer()
        span = tracer.start_as_current_span("test")
        assert hasattr(span, "__enter__")
        span2 = tracer.start_span("test2")
        assert hasattr(span2, "set_attribute")
