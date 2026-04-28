"""Tests for the syslog file handler."""

import logging
import os
from pathlib import Path

import pytest

import decnet.logging.file_handler as fh


@pytest.fixture(autouse=True)
def reset_handler(tmp_path, monkeypatch):
    """Reset the module-level logger between tests."""
    monkeypatch.setattr(fh, "_handler", None)
    monkeypatch.setattr(fh, "_logger", None)
    monkeypatch.setenv(fh._LOG_FILE_ENV, str(tmp_path / "test.log"))
    yield
    # Remove handlers to avoid file lock issues on next test
    if fh._logger is not None:
        for h in list(fh._logger.handlers):
            h.close()
            fh._logger.removeHandler(h)
    fh._handler = None
    fh._logger = None


def test_write_creates_log_file(tmp_path):
    log_path = tmp_path / "decnet.log"
    os.environ[fh._LOG_FILE_ENV] = str(log_path)
    fh.write_syslog("<134>1 2026-04-04T12:00:00+00:00 h svc - e - test message")
    assert log_path.exists()
    assert "test message" in log_path.read_text()


def test_write_appends_multiple_lines(tmp_path):
    log_path = tmp_path / "decnet.log"
    os.environ[fh._LOG_FILE_ENV] = str(log_path)
    for i in range(3):
        fh.write_syslog(f"<134>1 ts host svc - event{i} -")
    lines = log_path.read_text().splitlines()
    assert len(lines) == 3
    assert "event0" in lines[0]
    assert "event2" in lines[2]


def test_get_log_path_default(monkeypatch):
    monkeypatch.delenv(fh._LOG_FILE_ENV, raising=False)
    assert fh.get_log_path() == Path(fh._DEFAULT_LOG_FILE)


def test_get_log_path_custom(monkeypatch, tmp_path):
    custom = str(tmp_path / "custom.log")
    monkeypatch.setenv(fh._LOG_FILE_ENV, custom)
    assert fh.get_log_path() == Path(custom)


def test_rotating_handler_configured(tmp_path):
    log_path = tmp_path / "r.log"
    os.environ[fh._LOG_FILE_ENV] = str(log_path)
    logger = fh._get_logger()
    handler = logger.handlers[0]
    assert isinstance(handler, logging.handlers.RotatingFileHandler)
    assert handler.maxBytes == fh._MAX_BYTES
    assert handler.backupCount == fh._BACKUP_COUNT


def test_write_syslog_does_not_raise_on_bad_path(monkeypatch):
    monkeypatch.setenv(fh._LOG_FILE_ENV, "/no/such/dir/that/exists/decnet.log")
    # Should not raise — falls back to StreamHandler
    fh.write_syslog("<134>1 ts h svc - e -")
