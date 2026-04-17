"""
Pydantic models for DECNET configuration and runtime state.
State is persisted to decnet-state.json in the working directory.
"""

import json
import logging
import os
import socket as _socket
from datetime import datetime, timezone
from pathlib import Path

from decnet.models import DeckyConfig, DecnetConfig  # noqa: F401

from decnet.distros import random_hostname as _random_hostname

# ---------------------------------------------------------------------------
# RFC 5424 syslog formatter
# ---------------------------------------------------------------------------
# Severity mapping: Python level → syslog severity (RFC 5424 §6.2.1)
_SYSLOG_SEVERITY: dict[int, int] = {
    logging.CRITICAL: 2,  # Critical
    logging.ERROR:    3,  # Error
    logging.WARNING:  4,  # Warning
    logging.INFO:     6,  # Informational
    logging.DEBUG:    7,  # Debug
}
_FACILITY_LOCAL0 = 16  # local0 (RFC 5424 §6.2.1 / POSIX)


class Rfc5424Formatter(logging.Formatter):
    """Formats log records as RFC 5424 syslog messages.

    Output:
        <PRIVAL>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

    Example:
        <134>1 2026-04-12T21:48:03.123456+00:00 host decnet 1234 decnet.config - Dev mode active
    """

    _hostname: str = _socket.gethostname()
    _app: str = "decnet"

    def format(self, record: logging.LogRecord) -> str:
        severity = _SYSLOG_SEVERITY.get(record.levelno, 6)
        prival   = (_FACILITY_LOCAL0 * 8) + severity
        ts       = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="microseconds")
        msg      = record.getMessage()
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        app = getattr(record, "decnet_component", self._app)
        return (
            f"<{prival}>1 {ts} {self._hostname} {app}"
            f" {os.getpid()} {record.name} - {msg}"
        )


def _configure_logging(dev: bool) -> None:
    """Install RFC 5424 handlers on the root logger (idempotent).

    Always adds a StreamHandler (stderr).  Also adds a RotatingFileHandler
    writing to DECNET_SYSTEM_LOGS (default: decnet.system.log in $PWD) so
    all microservice daemons — which redirect stderr to /dev/null — still
    produce readable logs.  File handler is skipped under pytest.
    """
    import logging.handlers as _lh

    root = logging.getLogger()
    # Guard: if our StreamHandler is already installed, all handlers are set.
    if any(isinstance(h, logging.StreamHandler) and isinstance(h.formatter, Rfc5424Formatter)
           for h in root.handlers):
        return

    fmt = Rfc5424Formatter()
    root.setLevel(logging.DEBUG if dev else logging.INFO)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    root.addHandler(stream_handler)

    # Skip the file handler during pytest runs to avoid polluting the test cwd.
    _in_pytest = any(k.startswith("PYTEST") for k in os.environ)
    if not _in_pytest:
        _log_path = os.environ.get("DECNET_SYSTEM_LOGS", "decnet.system.log")
        file_handler = _lh.RotatingFileHandler(
            _log_path,
            mode="a",
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
        # Drop root ownership when invoked via sudo so non-root follow-up
        # commands (e.g. `decnet api` after `sudo decnet deploy`) can append.
        from decnet.privdrop import chown_to_invoking_user
        chown_to_invoking_user(_log_path)


_dev = os.environ.get("DECNET_DEVELOPER", "").lower() == "true"
_configure_logging(_dev)

log = logging.getLogger(__name__)

if _dev:
    log.debug("Developer mode: debug logging active")

# Calculate absolute path to the project root (where the config file resides)
_ROOT: Path = Path(__file__).parent.parent.absolute()
STATE_FILE: Path = _ROOT / "decnet-state.json"
DEFAULT_MUTATE_INTERVAL: int = 30  # default rotation interval in minutes


def random_hostname(distro_slug: str = "debian") -> str:
    return _random_hostname(distro_slug)


def save_state(config: DecnetConfig, compose_path: Path) -> None:
    payload = {
        "config": config.model_dump(),
        "compose_path": str(compose_path),
    }
    STATE_FILE.write_text(json.dumps(payload, indent=2))


def load_state() -> tuple[DecnetConfig, Path] | None:
    if not STATE_FILE.exists():
        return None
    data = json.loads(STATE_FILE.read_text())
    return DecnetConfig(**data["config"]), Path(data["compose_path"])


def clear_state() -> None:
    if STATE_FILE.exists():
        STATE_FILE.unlink()
