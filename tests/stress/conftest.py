# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Stress-test fixtures: real uvicorn server + out-of-process Locust runner.

Locust is run via its CLI in a fresh subprocess so its gevent monkey-patching
happens before ssl/urllib3 are imported. Running it in-process here causes a
RecursionError in urllib3's create_urllib3_context on Python 3.11+.
"""

import csv
import json
import multiprocessing
import os
import sys
import time
import socket
import subprocess
from pathlib import Path

import pytest
import requests


# ---------------------------------------------------------------------------
# Configuration (env-var driven for CI flexibility)
# ---------------------------------------------------------------------------
STRESS_USERS = int(os.environ.get("STRESS_USERS", "1000"))
STRESS_SPAWN_RATE = int(os.environ.get("STRESS_SPAWN_RATE", "50"))
STRESS_DURATION = int(os.environ.get("STRESS_DURATION", "60"))
STRESS_WORKERS = int(os.environ.get("STRESS_WORKERS", str(min(multiprocessing.cpu_count(), 4))))

ADMIN_USER = "admin"
ADMIN_PASS = "test-password-123"
JWT_SECRET = "stable-test-secret-key-at-least-32-chars-long"

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_LOCUSTFILE = Path(__file__).resolve().parent / "locustfile.py"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(url: str, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code in (200, 401, 503):
                return
        except requests.RequestException:
            # ConnectionError / ReadTimeout / anything else transient — the
            # server is either not up yet or too busy to respond in time.
            pass
        time.sleep(0.1)
    raise TimeoutError(f"Server not ready at {url}")


from contextlib import contextmanager


@contextmanager
def _start_stress_server():
    """Spawn a uvicorn for stress testing; yield base_url; tear down on exit."""
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("DECNET_")}
    env.update({
        "DECNET_JWT_SECRET": JWT_SECRET,
        "DECNET_ADMIN_PASSWORD": ADMIN_PASS,
        "DECNET_DEVELOPER": "false",
        "DECNET_DEVELOPER_TRACING": "false",
        "DECNET_DB_TYPE": "sqlite",
        "DECNET_MODE": "master",
        # Locust hammers /auth/login from a single host as a single
        # user — the production 10/5min per-IP + per-user limits would
        # kill ramp-up past the 11th virtual user. Stress tests are
        # measuring throughput, not rate-limiting; disable in this
        # subprocess only.
        "DECNET_LIMITER_ENABLED": "false",
    })
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
        try:
            _wait_for_server(f"{base_url}/api/v1/health", timeout=60.0)
        except TimeoutError:
            proc.terminate()
            try:
                out, err = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
            raise TimeoutError(
                f"uvicorn did not become ready.\n"
                f"--- stdout ---\n{out.decode(errors='replace')}\n"
                f"--- stderr ---\n{err.decode(errors='replace')}"
            )
        yield base_url
    finally:
        # Drop any cached admin token for the dying host so the next server
        # gets a fresh login instead of presenting a JWT signed against a
        # stale process state.
        _TOKEN_CACHE.pop(base_url, None)
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture(scope="function")
def stress_server():
    # Function-scoped: every stress test gets its own clean uvicorn. Sharing
    # a server across baseline → spike → sustained left the later runs with
    # a half-dead pool (0-request symptom). Cost is ~5s of startup per test.
    """Start a real uvicorn server for stress testing."""
    with _start_stress_server() as base_url:
        yield base_url


# Re-exported so tests can spin up additional servers within a single test
# (e.g. test_stress_sustained needs a fresh uvicorn between phases — phase 1
# leaves keep-alive connections that wedge phase 2 into 0 recorded requests).
start_stress_server = _start_stress_server


@pytest.fixture
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


# ---------------------------------------------------------------------------
# Locust subprocess runner + stats shim
# ---------------------------------------------------------------------------

class _StatsEntry:
    """Shim mimicking locust.stats.StatsEntry for the fields our tests use."""
    def __init__(self, row: dict, percentile_rows: dict):
        self.method = row.get("Type", "") or ""
        self.name = row.get("Name", "")
        self.num_requests = int(float(row.get("Request Count", 0) or 0))
        self.num_failures = int(float(row.get("Failure Count", 0) or 0))
        self.avg_response_time = float(row.get("Average Response Time", 0) or 0)
        self.min_response_time = float(row.get("Min Response Time", 0) or 0)
        self.max_response_time = float(row.get("Max Response Time", 0) or 0)
        self.total_rps = float(row.get("Requests/s", 0) or 0)
        self._percentiles = percentile_rows  # {0.5: ms, 0.95: ms, ...}

    def get_response_time_percentile(self, p: float):
        # Accept either 0.99 or 99 form; normalize to 0..1
        if p > 1:
            p = p / 100.0
        # Exact match first
        if p in self._percentiles:
            return self._percentiles[p]
        # Fuzzy match on closest declared percentile
        if not self._percentiles:
            return 0
        closest = min(self._percentiles.keys(), key=lambda k: abs(k - p))
        return self._percentiles[closest]


class _Stats:
    def __init__(self, total: _StatsEntry, entries: dict):
        self.total = total
        self.entries = entries


class _LocustEnv:
    def __init__(self, stats: _Stats):
        self.stats = stats


# Locust CSV column names for percentile fields (varies slightly by version).
_PCT_COL_MAP = {
    "50%": 0.50, "66%": 0.66, "75%": 0.75, "80%": 0.80,
    "90%": 0.90, "95%": 0.95, "98%": 0.98, "99%": 0.99,
    "99.9%": 0.999, "99.99%": 0.9999, "100%": 1.0,
}


def _parse_locust_csv(stats_csv: Path) -> _LocustEnv:
    if not stats_csv.exists():
        raise RuntimeError(f"locust stats csv missing: {stats_csv}")

    entries: dict = {}
    total: _StatsEntry | None = None

    with stats_csv.open() as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            pcts = {}
            for col, frac in _PCT_COL_MAP.items():
                v = row.get(col)
                if v not in (None, "", "N/A"):
                    try:
                        pcts[frac] = float(v)
                    except ValueError:
                        pass
            entry = _StatsEntry(row, pcts)
            if row.get("Name") == "Aggregated":
                total = entry
            else:
                key = (entry.method, entry.name)
                entries[key] = entry

    if total is None:
        # Fallback: synthesize a zero-row total
        total = _StatsEntry({}, {})
    return _LocustEnv(_Stats(total, entries))


_TOKEN_CACHE: dict[str, str] = {}


def _login_once(host: str, timeout: float) -> dict:
    last_exc: Exception | None = None
    # Retry through transient drain windows: between phases the API is
    # still flushing connections from the prior locust run, so the first
    # POST can sit in-queue past a single 15s timeout.
    for attempt in range(5):
        try:
            resp = requests.post(
                f"{host}/api/v1/auth/login",
                json={"username": ADMIN_USER, "password": ADMIN_PASS},
                timeout=timeout,
            )
            resp.raise_for_status()
            return resp.json()
        except (requests.Timeout, requests.ConnectionError) as e:
            last_exc = e
            time.sleep(2 ** attempt)
    raise RuntimeError(f"admin login failed after retries: {last_exc!r}")


def _fetch_admin_token(host: str) -> str:
    """Pre-fetch an admin token so locust virtual users don't all stampede
    /auth/login on_start. Bcrypt is CPU-bound; 1000 simultaneous logins under
    a 15s spike window means no user ever completes on_start and aggregated
    request count is 0.

    Cached per-host: the token is reusable across phases, so we don't pay
    a fresh /auth/login round-trip while a previous run is still draining.
    """
    cached = _TOKEN_CACHE.get(host)
    if cached:
        return cached

    body = _login_once(host, timeout=30)
    token = body["access_token"]
    if body.get("must_change_password"):
        requests.post(
            f"{host}/api/v1/auth/change-password",
            json={"old_password": ADMIN_PASS, "new_password": ADMIN_PASS},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        body = _login_once(host, timeout=30)
        token = body["access_token"]

    _TOKEN_CACHE[host] = token
    return token


def run_locust(host, users, spawn_rate, duration, _retry=False):
    """Run Locust in a subprocess (fresh Python, clean gevent monkey-patch)
    and return a stats shim compatible with the tests.
    """
    import tempfile

    tmp = tempfile.mkdtemp(prefix="locust-stress-")
    csv_prefix = Path(tmp) / "run"

    env = {k: v for k, v in os.environ.items()}
    # Ensure DecnetUser.on_start can log in with the right creds
    env.setdefault("DECNET_ADMIN_USER", ADMIN_USER)
    env.setdefault("DECNET_ADMIN_PASSWORD", ADMIN_PASS)
    # Pre-fetched token: locustfile picks this up and skips its own login.
    env["DECNET_STRESS_TOKEN"] = _fetch_admin_token(host)

    cmd = [
        sys.executable, "-m", "locust",
        "-f", str(_LOCUSTFILE),
        "--headless",
        "--host", host,
        "-u", str(users),
        "-r", str(spawn_rate),
        "-t", f"{duration}s",
        "--csv", str(csv_prefix),
        "--only-summary",
        "--loglevel", "WARNING",
        # Locust defaults to exit code 1 on any request failure. We have our
        # own per-test assertions for fail-rate; let the subprocess exit 0 so
        # we don't throw away an otherwise valid stats CSV.
        "--exit-code-on-error", "0",
    ]

    # Generous timeout: locust run-time + spawn ramp + shutdown grace
    wall_timeout = duration + max(30, users // max(1, spawn_rate)) + 30

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            cwd=str(_REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=wall_timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(
            f"locust subprocess timed out after {wall_timeout}s.\n"
            f"--- stdout ---\n{(e.stdout or b'').decode(errors='replace')}\n"
            f"--- stderr ---\n{(e.stderr or b'').decode(errors='replace')}"
        )

    # Locust exits non-zero on failure-rate threshold; we don't set one, so any
    # non-zero is a real error.
    if proc.returncode != 0:
        raise RuntimeError(
            f"locust subprocess exited {proc.returncode}.\n"
            f"--- stdout ---\n{proc.stdout.decode(errors='replace')}\n"
            f"--- stderr ---\n{proc.stderr.decode(errors='replace')}"
        )

    result = _parse_locust_csv(Path(str(csv_prefix) + "_stats.csv"))
    if result.stats.total.num_requests == 0 and not _retry:
        # Transient: server was mid-drain or connection storm RSTed before any
        # request landed. Wait for the API to respond cleanly, then retry once
        # before giving up.
        try:
            _wait_for_server(f"{host}/api/v1/health", timeout=15.0)
        except TimeoutError:
            pass
        time.sleep(2)
        return run_locust(host, users, spawn_rate, duration, _retry=True)
    if result.stats.total.num_requests == 0:
        raise RuntimeError(
            f"locust produced 0 requests (after 1 retry).\n"
            f"--- stdout ---\n{proc.stdout.decode(errors='replace')}\n"
            f"--- stderr ---\n{proc.stderr.decode(errors='replace')}"
        )
    return result
