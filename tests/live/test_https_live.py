import os
import queue
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
import requests
from urllib3.exceptions import InsecureRequestWarning

from tests.live.conftest import assert_rfc5424

_REPO_ROOT = Path(__file__).parent.parent.parent
_TEMPLATES = _REPO_ROOT / "templates"
_VENV_PYTHON = _REPO_ROOT / ".venv" / "bin" / "python"
_PYTHON = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else sys.executable


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_tls_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", port), timeout=0.5) as sock:
                with ctx.wrap_socket(sock, server_hostname="127.0.0.1"):
                    return True
        except (OSError, ssl.SSLError):
            time.sleep(0.1)
    return False


def _drain(q: queue.Queue, timeout: float = 2.0) -> list[str]:
    lines: list[str] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            lines.append(q.get(timeout=max(0.01, deadline - time.monotonic())))
        except queue.Empty:
            break
    return lines


def _generate_self_signed_cert(cert_path: str, key_path: str) -> None:
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-subj", "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )


class _HTTPSServiceProcess:
    """Manages an HTTPS service subprocess with TLS cert generation."""

    def __init__(self, port: int, cert_path: str, key_path: str):
        template_dir = _TEMPLATES / "https"
        env = {
            **os.environ,
            "NODE_NAME": "test-node",
            "PORT": str(port),
            "PYTHONPATH": str(template_dir),
            "LOG_TARGET": "",
            "TLS_CERT": cert_path,
            "TLS_KEY": key_path,
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
def https_service():
    """Start an HTTPS server with a temporary self-signed cert."""
    started: list[_HTTPSServiceProcess] = []
    tmp_dirs: list[tempfile.TemporaryDirectory] = []

    def _start() -> tuple[int, callable]:
        port = _free_port()
        tmp = tempfile.TemporaryDirectory()
        tmp_dirs.append(tmp)
        cert_path = os.path.join(tmp.name, "cert.pem")
        key_path = os.path.join(tmp.name, "key.pem")
        _generate_self_signed_cert(cert_path, key_path)

        svc = _HTTPSServiceProcess(port, cert_path, key_path)
        started.append(svc)
        if not _wait_for_tls_port(port):
            svc.stop()
            pytest.fail(f"HTTPS service did not bind to port {port} within 10s")
        svc.drain(timeout=0.3)
        return port, svc.drain

    yield _start

    for svc in started:
        svc.stop()
    for tmp in tmp_dirs:
        tmp.cleanup()


@pytest.mark.live
class TestHTTPSLive:
    def test_get_request_logged(self, https_service):
        port, drain = https_service()
        resp = requests.get(
            f"https://127.0.0.1:{port}/admin", timeout=5, verify=False,
        )
        assert resp.status_code == 403
        lines = drain()
        assert_rfc5424(lines, service="https", event_type="request")

    def test_tls_handshake(self, https_service):
        port, drain = https_service()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls:
                assert tls.version() is not None

    def test_server_header_set(self, https_service):
        port, drain = https_service()
        resp = requests.get(
            f"https://127.0.0.1:{port}/", timeout=5, verify=False,
        )
        assert "Server" in resp.headers
        assert resp.headers["Server"] != ""

    def test_post_body_logged(self, https_service):
        port, drain = https_service()
        requests.post(
            f"https://127.0.0.1:{port}/login",
            data={"username": "admin", "password": "secret"},
            timeout=5,
            verify=False,
        )
        lines = drain()
        assert any("body=" in line for line in lines if "request" in line), (
            "Expected 'body=' in request log line. Got:\n" + "\n".join(lines[:10])
        )

    def test_method_and_path_in_log(self, https_service):
        port, drain = https_service()
        requests.get(
            f"https://127.0.0.1:{port}/secret/file.txt", timeout=5, verify=False,
        )
        lines = drain()
        matched = assert_rfc5424(lines, service="https", event_type="request")
        assert "GET" in matched or 'method="GET"' in matched
        assert "/secret/file.txt" in matched or 'path="/secret/file.txt"' in matched
