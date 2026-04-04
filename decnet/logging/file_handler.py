from __future__ import annotations
"""
Rotating file handler for DECNET syslog output.

Writes RFC 5424 syslog lines to a local file.
Path is controlled by the DECNET_LOG_FILE environment variable
(default: /var/log/decnet/decnet.log).
"""

import logging
import logging.handlers
import os
from pathlib import Path

_LOG_FILE_ENV = "DECNET_LOG_FILE"
_DEFAULT_LOG_FILE = "/var/log/decnet/decnet.log"
_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
_BACKUP_COUNT = 5

_handler: logging.handlers.RotatingFileHandler | None = None
_logger: logging.Logger | None = None


def _get_logger() -> logging.Logger:
    global _handler, _logger
    if _logger is not None:
        return _logger

    log_path = Path(os.environ.get(_LOG_FILE_ENV, _DEFAULT_LOG_FILE))
    log_path.parent.mkdir(parents=True, exist_ok=True)

    _handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    _handler.setFormatter(logging.Formatter("%(message)s"))

    _logger = logging.getLogger("decnet.syslog")
    _logger.setLevel(logging.DEBUG)
    _logger.propagate = False
    _logger.addHandler(_handler)

    return _logger


def write_syslog(line: str) -> None:
    """Write a single RFC 5424 syslog line to the rotating log file."""
    try:
        _get_logger().info(line)
    except Exception:
        pass


def get_log_path() -> Path:
    """Return the configured log file path (for tests/inspection)."""
    return Path(os.environ.get(_LOG_FILE_ENV, _DEFAULT_LOG_FILE))
