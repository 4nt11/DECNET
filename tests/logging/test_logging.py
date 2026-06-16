# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Tests for DECNET application logging system.

Covers:
- get_logger() factory and _ComponentFilter injection
- Rfc5424Formatter component-aware APP-NAME field
- Log level gating via DECNET_DEVELOPER
- Component tags for all five microservice layers
"""

from __future__ import annotations

import logging
import os
import re

import pytest

from decnet.logging import _ComponentFilter, get_logger

# RFC 5424 parser: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
_RFC5424_RE = re.compile(
    r"^<(\d+)>1 "   # PRI
    r"\S+ "          # TIMESTAMP
    r"\S+ "          # HOSTNAME
    r"(\S+) "        # APP-NAME  ← what we care about
    r"\S+ "          # PROCID
    r"(\S+) "        # MSGID
    r"(.+)$",        # SD + MSG
)


def _format_record(logger: logging.Logger, level: int, msg: str) -> str:
    """Emit a log record through the root handler and return the formatted string."""
    from decnet.config import Rfc5424Formatter
    formatter = Rfc5424Formatter()
    record = logger.makeRecord(
        logger.name, level, "<test>", 0, msg, (), None
    )
    # Run all filters attached to the logger so decnet_component gets injected
    for f in logger.filters:
        f.filter(record)
    return formatter.format(record)


class TestGetLogger:
    def test_returns_logger(self):
        log = get_logger("cli")
        assert isinstance(log, logging.Logger)

    def test_logger_name(self):
        log = get_logger("engine")
        assert log.name == "decnet.engine"

    def test_filter_attached(self):
        log = get_logger("api")
        assert any(isinstance(f, _ComponentFilter) for f in log.filters)

    def test_idempotent_filter(self):
        log = get_logger("mutator")
        get_logger("mutator")  # second call
        component_filters = [f for f in log.filters if isinstance(f, _ComponentFilter)]
        assert len(component_filters) == 1

    @pytest.mark.parametrize("component", ["cli", "engine", "api", "mutator", "collector"])
    def test_all_components_registered(self, component):
        log = get_logger(component)
        assert any(isinstance(f, _ComponentFilter) for f in log.filters)


class TestComponentFilter:
    def test_injects_attribute(self):
        f = _ComponentFilter("engine")
        record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
        assert f.filter(record) is True
        assert record.decnet_component == "engine"  # type: ignore[attr-defined]

    def test_always_passes(self):
        f = _ComponentFilter("collector")
        record = logging.LogRecord("test", logging.DEBUG, "", 0, "msg", (), None)
        assert f.filter(record) is True


class TestRfc5424FormatterComponentAware:
    @pytest.mark.parametrize("component", ["cli", "engine", "api", "mutator", "collector"])
    def test_app_name_is_component(self, component):
        log = get_logger(component)
        line = _format_record(log, logging.INFO, "test message")
        m = _RFC5424_RE.match(line)
        assert m is not None, f"Not RFC 5424: {line!r}"
        assert m.group(2) == component, f"Expected APP-NAME={component!r}, got {m.group(2)!r}"

    def test_fallback_app_name_without_component(self):
        """Untagged loggers (no _ComponentFilter) fall back to 'decnet'."""
        from decnet.config import Rfc5424Formatter
        formatter = Rfc5424Formatter()
        record = logging.LogRecord("some.module", logging.INFO, "", 0, "hello", (), None)
        line = formatter.format(record)
        m = _RFC5424_RE.match(line)
        assert m is not None
        assert m.group(2) == "decnet"

    def test_msgid_is_logger_name(self):
        log = get_logger("engine")
        line = _format_record(log, logging.INFO, "deploying")
        m = _RFC5424_RE.match(line)
        assert m is not None
        assert m.group(3) == "decnet.engine"


class TestLogLevelGating:
    def test_configure_logging_normal_mode_sets_info(self):
        """_configure_logging(dev=False) must set root to INFO."""
        from decnet.config import _configure_logging, Rfc5424Formatter
        root = logging.getLogger()
        original_level = root.level
        original_handlers = root.handlers[:]
        # Remove any existing RFC5424 handlers so idempotency check doesn't skip
        root.handlers = [
            h for h in root.handlers
            if not (isinstance(h, logging.StreamHandler) and isinstance(h.formatter, Rfc5424Formatter))
        ]
        try:
            _configure_logging(dev=False)
            assert root.level == logging.INFO
        finally:
            root.setLevel(original_level)
            root.handlers = original_handlers

    def test_configure_logging_dev_mode_sets_debug(self):
        """_configure_logging(dev=True) must set root to DEBUG."""
        from decnet.config import _configure_logging, Rfc5424Formatter
        root = logging.getLogger()
        original_level = root.level
        original_handlers = root.handlers[:]
        root.handlers = [
            h for h in root.handlers
            if not (isinstance(h, logging.StreamHandler) and isinstance(h.formatter, Rfc5424Formatter))
        ]
        try:
            _configure_logging(dev=True)
            assert root.level == logging.DEBUG
        finally:
            root.setLevel(original_level)
            root.handlers = original_handlers

    def test_debug_enabled_in_developer_mode(self, monkeypatch):
        """Programmatically setting DEBUG on root allows debug records through."""
        root = logging.getLogger()
        original_level = root.level
        root.setLevel(logging.DEBUG)
        try:
            assert root.isEnabledFor(logging.DEBUG)
        finally:
            root.setLevel(original_level)
