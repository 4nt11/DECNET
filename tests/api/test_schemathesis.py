"""
Schemathesis contract tests — full compliance, all checks enabled.

Requires DECNET_DEVELOPER=true (set in tests/conftest.py) to expose /openapi.json.
"""
import pytest
import schemathesis as st
from schemathesis.checks import not_a_server_error
from schemathesis.specs.openapi.checks import (
    status_code_conformance,
    content_type_conformance,
    response_headers_conformance,
    response_schema_conformance,
    positive_data_acceptance,
    negative_data_rejection,
    missing_required_header,
    unsupported_method,
    use_after_free,
    ensure_resource_availability,
    ignored_auth,
)
from hypothesis import settings, Verbosity, HealthCheck
from decnet.web.auth import create_access_token

import subprocess
import socket
import sys
import atexit
import os
import time
from datetime import datetime, timezone
from pathlib import Path


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


LIVE_PORT = _free_port()
LIVE_SERVER_URL = f"http://127.0.0.1:{LIVE_PORT}"
TEST_SECRET = "test-secret-for-automated-fuzzing"

import decnet.web.auth
decnet.web.auth.SECRET_KEY = TEST_SECRET

TEST_TOKEN = create_access_token({"uuid": "00000000-0000-0000-0000-000000000001"})

ALL_CHECKS = (
    not_a_server_error,
    status_code_conformance,
    content_type_conformance,
    response_headers_conformance,
    response_schema_conformance,
    positive_data_acceptance,
    negative_data_rejection,
    missing_required_header,
    unsupported_method,
    use_after_free,
    ensure_resource_availability,
)

AUTH_CHECKS = (
    not_a_server_error,
    ignored_auth,
)


@st.hook
def before_call(context, case, *args):
    case.headers = case.headers or {}
    case.headers["Authorization"] = f"Bearer {TEST_TOKEN}"
    if case.path and case.path.endswith("/stream"):
        case.query = case.query or {}
        case.query["maxOutput"] = 0


def wait_for_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def start_automated_server() -> subprocess.Popen:
    uvicorn_bin = "uvicorn" if os.name != "nt" else "uvicorn.exe"
    uvicorn_path = str(Path(sys.executable).parent / uvicorn_bin)

    env = os.environ.copy()
    env["DECNET_DEVELOPER"] = "true"
    env["DECNET_CONTRACT_TEST"] = "true"
    env["DECNET_JWT_SECRET"] = TEST_SECRET
    # Schemathesis fires thousands of examples per endpoint; the login
    # bucket (10/5min per IP) trips on the second example and turns
    # every subsequent valid request into a RejectedPositiveData
    # failure. Disable the limiter for the fuzz subprocess — same
    # rationale as the load-testing knob in decnet/web/limiter.py.
    env["DECNET_LIMITER_ENABLED"] = "false"

    log_dir = Path(__file__).parent.parent.parent / "logs"
    log_dir.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_file = open(log_dir / f"fuzz_server_{LIVE_PORT}_{ts}.log", "w")

    proc = subprocess.Popen(
        [
            uvicorn_path,
            "decnet.web.api:app",
            "--host", "127.0.0.1",
            "--port", str(LIVE_PORT),
            "--log-level", "info",
        ],
        env=env,
        stdout=log_file,
        stderr=log_file,
    )

    atexit.register(proc.terminate)
    atexit.register(log_file.close)

    if not wait_for_port(LIVE_PORT):
        proc.terminate()
        raise RuntimeError(f"Automated server failed to start on port {LIVE_PORT}")

    return proc


_server_proc = start_automated_server()

schema = st.openapi.from_url(f"{LIVE_SERVER_URL}/openapi.json")


@pytest.mark.fuzz
@st.pytest.parametrize(api=schema)
@settings(
    max_examples=3000,
    deadline=None,
    verbosity=Verbosity.debug,
    suppress_health_check=[
        HealthCheck.filter_too_much,
        HealthCheck.too_slow,
        HealthCheck.data_too_large,
    ],
)
def test_schema_compliance(case):
    """Full contract test: valid + invalid inputs, all response checks."""
    case.call_and_validate(checks=ALL_CHECKS)


@pytest.mark.fuzz
@st.pytest.parametrize(api=schema)
@settings(
    max_examples=500,
    deadline=None,
    verbosity=Verbosity.normal,
    suppress_health_check=[
        HealthCheck.filter_too_much,
        HealthCheck.too_slow,
    ],
)
def test_auth_enforcement(case):
    """Verify every protected endpoint rejects requests with no token."""
    case.headers = {
        k: v for k, v in (case.headers or {}).items()
        if k.lower() != "authorization"
    }
    if case.path and case.path.endswith("/stream"):
        case.query = case.query or {}
        case.query["maxOutput"] = 0
    case.call_and_validate(checks=AUTH_CHECKS)
