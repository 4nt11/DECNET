"""
DECNET application logging helpers.

Usage:
    from decnet.logging import get_logger
    log = get_logger("engine")   # APP-NAME in RFC 5424 output becomes "engine"

The returned logger propagates to the root logger (configured in config.py with
Rfc5424Formatter), so level control via DECNET_DEVELOPER still applies globally.
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
        record.decnet_component = self.component  # type: ignore[attr-defined]
        return True


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
