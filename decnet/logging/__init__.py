# SPDX-License-Identifier: AGPL-3.0-or-later
"""
DECNET application logging helpers.

Usage:
    from decnet.logging import get_logger
    log = get_logger("engine")   # APP-NAME in RFC 5424 output becomes "engine"

The returned logger propagates to the root logger (configured in config.py with
Rfc5424Formatter), so level control via DECNET_DEVELOPER still applies globally.

When ``DECNET_DEVELOPER_TRACING`` is active, every LogRecord is enriched with
``otel_trace_id`` and ``otel_span_id`` from the current OTEL span context.
This lets you correlate log lines with Jaeger traces — click a log entry and
jump straight to the span that produced it.
"""

from __future__ import annotations

import logging


class _ComponentFilter(logging.Filter):
    """Injects *decnet_component* onto every LogRecord so Rfc5424Formatter can
    use it as the RFC 5424 APP-NAME field instead of the hardcoded "decnet"."""

    def __init__(self, component: str) -> None:
        super().__init__()
        self.component = component

    def filter(self, record: logging.LogRecord) -> bool:
        record.decnet_component = self.component
        return True


class _TraceContextFilter(logging.Filter):
    """Injects ``otel_trace_id`` and ``otel_span_id`` onto every LogRecord
    from the active OTEL span context.

    Installed once by ``enable_trace_context()`` on the root ``decnet`` logger
    so all child loggers inherit the enrichment via propagation.

    When no span is active, both fields are set to ``"0"`` (cheap string
    comparison downstream, no None-checks needed).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            from opentelemetry import trace
            span = trace.get_current_span()
            ctx = span.get_span_context()
            if ctx and ctx.trace_id:
                record.otel_trace_id = format(ctx.trace_id, "032x")
                record.otel_span_id = format(ctx.span_id, "016x")
            else:
                record.otel_trace_id = "0"
                record.otel_span_id = "0"
        except Exception:
            record.otel_trace_id = "0"
            record.otel_span_id = "0"
        return True


_trace_filter_installed: bool = False


def enable_trace_context() -> None:
    """Install the OTEL trace-context filter on the root ``decnet`` logger.

    Called once from ``decnet.telemetry.setup_tracing()`` after the
    TracerProvider is initialised.  Safe to call multiple times (idempotent).
    """
    global _trace_filter_installed
    if _trace_filter_installed:
        return
    root = logging.getLogger("decnet")
    root.addFilter(_TraceContextFilter())
    _trace_filter_installed = True


def get_logger(component: str) -> logging.Logger:
    """Return a named logger that self-identifies as *component* in RFC 5424.

    Valid components: cli, engine, api, mutator, collector.

    The logger is named ``decnet.<component>`` and propagates normally, so the
    root handler (Rfc5424Formatter + level gate from DECNET_DEVELOPER) handles
    output. Calling this function multiple times for the same component is safe.
    """
    logger = logging.getLogger(f"decnet.{component}")
    if not any(isinstance(f, _ComponentFilter) for f in logger.filters):
        logger.addFilter(_ComponentFilter(component))
    return logger
