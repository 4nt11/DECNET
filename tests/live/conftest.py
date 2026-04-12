"""
Shared fixtures for live subprocess service tests.

Each fixture starts the real server.py in a subprocess, captures its stdout
(RFC 5424 syslog lines) via a background reader thread, polls the port for
readiness, yields (port, log_drain_fn), then tears down.
"""

import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Generator
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parent.parent.parent
_TEMPLATES = _REPO_ROOT / "templates"

# Prefer the project venv's Python (has Flask, Twisted, etc.) over system Python
_VENV_PYTHON = _REPO_ROOT / ".venv" / "bin" / "python"
_PYTHON = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else sys.executable

# RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME - MSGID [SD] MSG?
# Use search (not match) so lines prefixed by Twisted timestamps are handled.
_RFC5424_RE = re.compile(r"<\d+>1 \S+ \S+ \S+ - \S+ ")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def _drain(q: queue.Queue, timeout: float = 2.0) -> list[str]:
    """Drain all lines from the log queue within *timeout* seconds."""
    lines: list[str] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            lines.append(q.get(timeout=max(0.01, deadline - time.monotonic())))
        except queue.Empty:
            break
    return lines


def assert_rfc5424(
    lines: list[str],
    *,
    service: str | None = None,
    event_type: str | None = None,
    **fields: str,
) -> str:
    """
    Assert that at least one line in *lines* is a valid RFC 5424 log entry
    matching the given criteria. Returns the first matching line.
    """
    for line in lines:
        if not _RFC5424_RE.search(line):
            continue
        if service and f" {service} " not in line:
            continue
        if event_type and event_type not in line:
            continue
        if all(f'{k}="{v}"' in line or f"{k}={v}" in line for k, v in fields.items()):
            return line
    criteria = {"service": service, "event_type": event_type, **fields}
    raise AssertionError(
        f"No RFC 5424 line matching {criteria!r} found among {len(lines)} lines:\n"
        + "\n".join(f"  {line!r}" for line in lines[:20])
    )


class _ServiceProcess:
    """Manages a live service subprocess and its stdout log queue."""

    def __init__(self, service: str, port: int):
        template_dir = _TEMPLATES / service
        env = {
            **os.environ,
            "NODE_NAME": "test-node",
            "PORT": str(port),
            "PYTHONPATH": str(template_dir),
            "LOG_TARGET": "",
        }
        self._proc = subprocess.Popen(
            [_PYTHON, str(template_dir / "server.py")],
            cwd=str(template_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )
        self._q: queue.Queue = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            self._q.put(line.rstrip("\n"))

    def drain(self, timeout: float = 2.0) -> list[str]:
        return _drain(self._q, timeout)

    def stop(self) -> None:
        self._proc.terminate()
        try:
            self._proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()


@pytest.fixture
def live_service() -> Generator:
    """
    Factory fixture: call live_service(service_name) to start a server.

    Usage::

        def test_foo(live_service):
            port, drain = live_service("redis")
            # connect to 127.0.0.1:port ...
            lines = drain()
            assert_rfc5424(lines, service="redis", event_type="auth")
    """
    started: list[_ServiceProcess] = []

    def _start(service: str) -> tuple[int, callable]:
        port = _free_port()
        svc = _ServiceProcess(service, port)
        started.append(svc)
        if not _wait_for_port(port):
            svc.stop()
            pytest.fail(f"Service '{service}' did not bind to port {port} within 8s")
        # Flush startup noise before the test begins
        svc.drain(timeout=0.3)
        return port, svc.drain

    yield _start

    for svc in started:
        svc.stop()
