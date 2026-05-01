"""
DECNET OpenTelemetry tracing integration.

Controlled entirely by ``DECNET_DEVELOPER_TRACING``.  When disabled (the
default), every public export is a zero-cost no-op: no OTEL SDK imports, no
monkey-patching, no middleware, and ``@traced`` returns the original function
object unwrapped.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable, TypeVar, overload

from decnet.env import DECNET_DEVELOPER_TRACING, DECNET_OTEL_ENDPOINT
from decnet.logging import get_logger

log = get_logger("api")

F = TypeVar("F", bound=Callable[..., Any])

_ENABLED: bool = DECNET_DEVELOPER_TRACING

# ---------------------------------------------------------------------------
# Lazy OTEL imports — only when tracing is enabled
# ---------------------------------------------------------------------------

_tracer_provider: Any = None  # TracerProvider | None


def _init_provider() -> None:
    """Initialise the global TracerProvider (called once from setup_tracing)."""
    global _tracer_provider

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource

    resource = Resource.create({
        "service.name": "decnet",
        "service.version": "0.2.0",
    })
    _tracer_provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=DECNET_OTEL_ENDPOINT, insecure=True)
    _tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(_tracer_provider)
    log.info("OTEL tracing enabled endpoint=%s", DECNET_OTEL_ENDPOINT)


def setup_tracing(app: Any) -> None:
    """Configure the OTEL TracerProvider and instrument FastAPI.

    Call once from the FastAPI lifespan, after DB init.  No-op when
    ``DECNET_DEVELOPER_TRACING`` is not ``"true"``.
    """
    if not _ENABLED:
        return

    try:
        _init_provider()
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
        from decnet.logging import enable_trace_context
        enable_trace_context()
        log.info("FastAPI auto-instrumentation active, log-trace correlation enabled")
    except Exception as exc:
        log.warning("OTEL setup failed — continuing without tracing: %s", exc)


def shutdown_tracing() -> None:
    """Flush and shut down the tracer provider.  Safe to call when disabled."""
    if _tracer_provider is not None:
        try:
            _tracer_provider.shutdown()
        except Exception:  # nosec B110 — best-effort tracer shutdown
            pass


# ---------------------------------------------------------------------------
# get_tracer — mirrors get_logger(component) pattern
# ---------------------------------------------------------------------------

class _NoOpSpan:
    """Minimal stand-in so ``with get_tracer(...).start_as_current_span(...)``
    works when tracing is disabled."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, *args: Any, **kwargs: Any) -> None:
        pass

    def record_exception(self, exc: BaseException) -> None:
        pass

    def __enter__(self) -> "_NoOpSpan":
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class _NoOpTracer:
    """Returned by ``get_tracer()`` when tracing is disabled."""

    def start_as_current_span(self, name: str, **kwargs: Any) -> _NoOpSpan:
        return _NoOpSpan()

    def start_span(self, name: str, **kwargs: Any) -> _NoOpSpan:
        return _NoOpSpan()


_tracers: dict[str, Any] = {}


def get_tracer(component: str) -> Any:
    """Return an OTEL Tracer (or a no-op stand-in) for *component*."""
    if not _ENABLED:
        return _NoOpTracer()

    if component not in _tracers:
        from opentelemetry import trace
        _tracers[component] = trace.get_tracer(f"decnet.{component}")
    return _tracers[component]


# ---------------------------------------------------------------------------
# @traced decorator — async + sync, zero overhead when disabled
# ---------------------------------------------------------------------------

@overload
def traced(fn: F) -> F: ...
@overload
def traced(name: str) -> Callable[[F], F]: ...


def traced(fn: Any = None, *, name: str | None = None) -> Any:  # type: ignore[misc]
    """Decorator that wraps a function in an OTEL span.

    Usage::

        @traced                          # span name = "module.func"
        async def my_worker(): ...

        @traced("custom.span.name")      # explicit span name
        def my_sync_func(): ...

    When ``DECNET_DEVELOPER_TRACING`` is disabled the original function is
    returned **unwrapped** — zero overhead on every call.
    """
    # Handle @traced("name") vs @traced vs @traced(name="name")
    if fn is None and name is not None:
        # Called as @traced("name") or @traced(name="name")
        def decorator(f: F) -> F:
            return _wrap(f, name)
        return decorator
    if fn is not None and isinstance(fn, str):
        # Called as @traced("name") — fn is actually the name string
        span_name = fn
        def decorator(f: F) -> F:
            return _wrap(f, span_name)
        return decorator
    if fn is not None and callable(fn):
        # Called as @traced (no arguments)
        return _wrap(fn, None)
    # Fallback: @traced() with no args
    def _fallback_decorator(f: F) -> F:
        return _wrap(f, name)
    return _fallback_decorator


def _wrap(fn: F, span_name: str | None) -> F:
    """Wrap *fn* in a span. Returns *fn* unchanged when tracing is off."""
    if not _ENABLED:
        return fn

    resolved_name = span_name or f"{fn.__module__.rsplit('.', 1)[-1]}.{fn.__qualname__}"

    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer(fn.__module__.split(".")[-1])
            with tracer.start_as_current_span(resolved_name) as span:
                try:
                    result = await fn(*args, **kwargs)
                    return result
                except Exception as exc:
                    span.record_exception(exc)
                    raise
        return async_wrapper  # type: ignore[return-value]
    else:
        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer(fn.__module__.split(".")[-1])
            with tracer.start_as_current_span(resolved_name) as span:
                try:
                    result = fn(*args, **kwargs)
                    return result
                except Exception as exc:
                    span.record_exception(exc)
                    raise
        return sync_wrapper  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# TracedRepository — proxy wrapper for BaseRepository
# ---------------------------------------------------------------------------

def wrap_repository(repo: Any) -> Any:
    """Wrap *repo* in a dynamic tracing proxy.  Returns *repo* unchanged when disabled.

    Instead of mirroring every method signature (which drifts when concrete
    repos add extra kwargs beyond the ABC), this proxy introspects the inner
    repo at construction time and wraps every public async method in a span
    via ``__getattr__``.  Sync attributes are forwarded directly.
    """
    if not _ENABLED:
        return repo

    tracer = get_tracer("db")

    class TracedRepository:
        """Dynamic proxy — wraps every async method call in a DB span."""

        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def __getattr__(self, name: str) -> Any:
            attr = getattr(self._inner, name)

            if asyncio.iscoroutinefunction(attr):
                @functools.wraps(attr)
                async def _traced_method(*args: Any, **kwargs: Any) -> Any:
                    with tracer.start_as_current_span(f"db.{name}") as span:
                        try:
                            return await attr(*args, **kwargs)
                        except Exception as exc:
                            span.record_exception(exc)
                            raise
                return _traced_method

            return attr

    return TracedRepository(repo)


# ---------------------------------------------------------------------------
# Cross-stage trace context propagation
# ---------------------------------------------------------------------------
# The DECNET pipeline is decoupled via JSON files:
#   collector -> .json file -> ingester -> DB -> profiler
#
# To show the full journey of an event in Jaeger, we embed W3C trace context
# into the JSON records.  The collector injects it; the ingester extracts it
# and continues the trace as a child span.

def inject_context(record: dict[str, Any]) -> None:
    """Inject current OTEL trace context into *record* under ``_trace``.

    No-op when tracing is disabled.  The ``_trace`` key is stripped by the
    ingester after extraction — it never reaches the DB.
    """
    if not _ENABLED:
        return
    try:
        from opentelemetry.propagate import inject
        carrier: dict[str, str] = {}
        inject(carrier)
        if carrier:
            record["_trace"] = carrier
    except Exception:  # nosec B110 — trace injection is optional
        pass


def extract_context(record: dict[str, Any]) -> Any:
    """Extract OTEL trace context from *record* and return it.

    Returns ``None`` when tracing is disabled or no context is present.
    Removes the ``_trace`` key from the record so it doesn't leak into the DB.
    """
    if not _ENABLED:
        record.pop("_trace", None)
        return None
    try:
        carrier = record.pop("_trace", None)
        if not carrier:
            return None
        from opentelemetry.propagate import extract
        return extract(carrier)
    except Exception:
        return None


def start_span_with_context(tracer: Any, name: str, context: Any = None) -> Any:
    """Start a span, optionally as a child of an extracted context.

    Returns a context manager span.  When *context* is ``None``, creates a
    root span (normal behavior).
    """
    if not _ENABLED:
        return _NoOpSpan()
    if context is not None:
        return tracer.start_as_current_span(name, context=context)
    return tracer.start_as_current_span(name)
