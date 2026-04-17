"""
Stress-test fixtures: real uvicorn server + programmatic Locust runner.
"""

import multiprocessing
import os
import sys
import time
import socket
import signal
import subprocess

import pytest
import requests


# ---------------------------------------------------------------------------
# Configuration (env-var driven for CI flexibility)
# ---------------------------------------------------------------------------
STRESS_USERS = int(os.environ.get("STRESS_USERS", "500"))
STRESS_SPAWN_RATE = int(os.environ.get("STRESS_SPAWN_RATE", "50"))
STRESS_DURATION = int(os.environ.get("STRESS_DURATION", "60"))
STRESS_WORKERS = int(os.environ.get("STRESS_WORKERS", str(min(multiprocessing.cpu_count(), 4))))

ADMIN_USER = "admin"
ADMIN_PASS = "test-password-123"
JWT_SECRET = "stable-test-secret-key-at-least-32-chars-long"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(url: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code in (200, 503):
                return
        except requests.ConnectionError:
            pass
        time.sleep(0.1)
    raise TimeoutError(f"Server not ready at {url}")


@pytest.fixture(scope="session")
def stress_server():
    """Start a real uvicorn server for stress testing."""
    port = _free_port()
    env = {
        **os.environ,
        "DECNET_JWT_SECRET": JWT_SECRET,
        "DECNET_ADMIN_PASSWORD": ADMIN_PASS,
        "DECNET_DEVELOPER": "true",
        "DECNET_DEVELOPER_TRACING": "false",
        "DECNET_DB_TYPE": "sqlite",
    }
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "decnet.web.api:app",
            "--host", "127.0.0.1",
            "--port", str(port),
            "--workers", str(STRESS_WORKERS),
            "--log-level", "warning",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_server(f"{base_url}/api/v1/health")
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture(scope="session")
def stress_token(stress_server):
    """Authenticate and return a valid admin JWT."""
    url = stress_server
    resp = requests.post(
        f"{url}/api/v1/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASS},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token = resp.json()["access_token"]

    # Clear must_change_password
    requests.post(
        f"{url}/api/v1/auth/change-password",
        json={"old_password": ADMIN_PASS, "new_password": ADMIN_PASS},
        headers={"Authorization": f"Bearer {token}"},
    )
    # Re-login for clean token
    resp2 = requests.post(
        f"{url}/api/v1/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASS},
    )
    return resp2.json()["access_token"]


def run_locust(host, users, spawn_rate, duration):
    """Run Locust programmatically and return the Environment with stats."""
    import gevent
    from locust.env import Environment
    from locust.stats import stats_printer, stats_history, StatsCSVFileWriter
    from tests.stress.locustfile import DecnetUser

    env = Environment(user_classes=[DecnetUser], host=host)
    env.create_local_runner()

    env.runner.start(users, spawn_rate=spawn_rate)

    # Let it run for the specified duration
    gevent.sleep(duration)

    env.runner.quit()
    env.runner.greenlet.join(timeout=10)

    return env
