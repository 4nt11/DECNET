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
from typing import Any, Callable, Optional, TypeVar, overload

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
        log.info("FastAPI auto-instrumentation active")
    except Exception as exc:
        log.warning("OTEL setup failed — continuing without tracing: %s", exc)


def shutdown_tracing() -> None:
    """Flush and shut down the tracer provider.  Safe to call when disabled."""
    if _tracer_provider is not None:
        try:
            _tracer_provider.shutdown()
        except Exception:
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


def traced(fn: Any = None, *, name: str | None = None) -> Any:
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
    def decorator(f: F) -> F:
        return _wrap(f, name)
    return decorator


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
    """Wrap *repo* in a tracing proxy.  Returns *repo* unchanged when disabled."""
    if not _ENABLED:
        return repo

    from decnet.web.db.repository import BaseRepository

    class TracedRepository(BaseRepository):
        """Proxy that creates a DB span around every BaseRepository call."""

        def __init__(self, inner: BaseRepository) -> None:
            self._inner = inner
            self._tracer = get_tracer("db")

        # --- Forward every ABC method through a span ---

        async def initialize(self) -> None:
            with self._tracer.start_as_current_span("db.initialize"):
                return await self._inner.initialize()

        async def add_log(self, log_data):
            with self._tracer.start_as_current_span("db.add_log"):
                return await self._inner.add_log(log_data)

        async def get_logs(self, limit=50, offset=0, search=None):
            with self._tracer.start_as_current_span("db.get_logs") as span:
                span.set_attribute("db.limit", limit)
                span.set_attribute("db.offset", offset)
                return await self._inner.get_logs(limit=limit, offset=offset, search=search)

        async def get_total_logs(self, search=None):
            with self._tracer.start_as_current_span("db.get_total_logs"):
                return await self._inner.get_total_logs(search=search)

        async def get_stats_summary(self):
            with self._tracer.start_as_current_span("db.get_stats_summary"):
                return await self._inner.get_stats_summary()

        async def get_deckies(self):
            with self._tracer.start_as_current_span("db.get_deckies"):
                return await self._inner.get_deckies()

        async def get_user_by_username(self, username):
            with self._tracer.start_as_current_span("db.get_user_by_username"):
                return await self._inner.get_user_by_username(username)

        async def get_user_by_uuid(self, uuid):
            with self._tracer.start_as_current_span("db.get_user_by_uuid"):
                return await self._inner.get_user_by_uuid(uuid)

        async def create_user(self, user_data):
            with self._tracer.start_as_current_span("db.create_user"):
                return await self._inner.create_user(user_data)

        async def update_user_password(self, uuid, password_hash, must_change_password=False):
            with self._tracer.start_as_current_span("db.update_user_password"):
                return await self._inner.update_user_password(uuid, password_hash, must_change_password)

        async def list_users(self):
            with self._tracer.start_as_current_span("db.list_users"):
                return await self._inner.list_users()

        async def delete_user(self, uuid):
            with self._tracer.start_as_current_span("db.delete_user"):
                return await self._inner.delete_user(uuid)

        async def update_user_role(self, uuid, role):
            with self._tracer.start_as_current_span("db.update_user_role"):
                return await self._inner.update_user_role(uuid, role)

        async def purge_logs_and_bounties(self):
            with self._tracer.start_as_current_span("db.purge_logs_and_bounties"):
                return await self._inner.purge_logs_and_bounties()

        async def add_bounty(self, bounty_data):
            with self._tracer.start_as_current_span("db.add_bounty"):
                return await self._inner.add_bounty(bounty_data)

        async def get_bounties(self, limit=50, offset=0, bounty_type=None, search=None):
            with self._tracer.start_as_current_span("db.get_bounties") as span:
                span.set_attribute("db.limit", limit)
                span.set_attribute("db.offset", offset)
                return await self._inner.get_bounties(limit=limit, offset=offset, bounty_type=bounty_type, search=search)

        async def get_total_bounties(self, bounty_type=None, search=None):
            with self._tracer.start_as_current_span("db.get_total_bounties"):
                return await self._inner.get_total_bounties(bounty_type=bounty_type, search=search)

        async def get_state(self, key):
            with self._tracer.start_as_current_span("db.get_state") as span:
                span.set_attribute("db.state_key", key)
                return await self._inner.get_state(key)

        async def set_state(self, key, value):
            with self._tracer.start_as_current_span("db.set_state") as span:
                span.set_attribute("db.state_key", key)
                return await self._inner.set_state(key, value)

        async def get_max_log_id(self):
            with self._tracer.start_as_current_span("db.get_max_log_id"):
                return await self._inner.get_max_log_id()

        async def get_logs_after_id(self, last_id, limit=500):
            with self._tracer.start_as_current_span("db.get_logs_after_id") as span:
                span.set_attribute("db.last_id", last_id)
                span.set_attribute("db.limit", limit)
                return await self._inner.get_logs_after_id(last_id, limit=limit)

        async def get_all_bounties_by_ip(self):
            with self._tracer.start_as_current_span("db.get_all_bounties_by_ip"):
                return await self._inner.get_all_bounties_by_ip()

        async def get_bounties_for_ips(self, ips):
            with self._tracer.start_as_current_span("db.get_bounties_for_ips") as span:
                span.set_attribute("db.ip_count", len(ips))
                return await self._inner.get_bounties_for_ips(ips)

        async def upsert_attacker(self, data):
            with self._tracer.start_as_current_span("db.upsert_attacker"):
                return await self._inner.upsert_attacker(data)

        async def upsert_attacker_behavior(self, attacker_uuid, data):
            with self._tracer.start_as_current_span("db.upsert_attacker_behavior"):
                return await self._inner.upsert_attacker_behavior(attacker_uuid, data)

        async def get_attacker_behavior(self, attacker_uuid):
            with self._tracer.start_as_current_span("db.get_attacker_behavior"):
                return await self._inner.get_attacker_behavior(attacker_uuid)

        async def get_behaviors_for_ips(self, ips):
            with self._tracer.start_as_current_span("db.get_behaviors_for_ips") as span:
                span.set_attribute("db.ip_count", len(ips))
                return await self._inner.get_behaviors_for_ips(ips)

        async def get_attacker_by_uuid(self, uuid):
            with self._tracer.start_as_current_span("db.get_attacker_by_uuid"):
                return await self._inner.get_attacker_by_uuid(uuid)

        async def get_attackers(self, limit=50, offset=0, search=None, sort_by="recent", service=None):
            with self._tracer.start_as_current_span("db.get_attackers") as span:
                span.set_attribute("db.limit", limit)
                span.set_attribute("db.offset", offset)
                return await self._inner.get_attackers(limit=limit, offset=offset, search=search, sort_by=sort_by, service=service)

        async def get_total_attackers(self, search=None, service=None):
            with self._tracer.start_as_current_span("db.get_total_attackers"):
                return await self._inner.get_total_attackers(search=search, service=service)

        async def get_attacker_commands(self, uuid, limit=50, offset=0, service=None):
            with self._tracer.start_as_current_span("db.get_attacker_commands") as span:
                span.set_attribute("db.limit", limit)
                span.set_attribute("db.offset", offset)
                return await self._inner.get_attacker_commands(uuid, limit=limit, offset=offset, service=service)

        # --- Catch-all for methods defined on concrete subclasses but not
        #     in the ABC (e.g. get_log_histogram). ---

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    return TracedRepository(repo)
