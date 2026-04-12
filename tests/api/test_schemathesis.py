"""
Schemathesis contract tests.

Generates requests from the OpenAPI spec and verifies that no input causes a 5xx.

Currently scoped to `not_a_server_error` only — full response-schema conformance
(including undocumented 401 responses) is blocked by DEBT-020 (missing error
response declarations across all protected endpoints). Once DEBT-020 is resolved,
replace the checks list with the default (remove the argument) for full compliance.

Requires DECNET_DEVELOPER=true (set in tests/conftest.py) to expose /openapi.json.
"""
import pytest
import schemathesis as st
from hypothesis import settings, Verbosity
from decnet.web.auth import create_access_token

import subprocess
import socket
import sys
import atexit
import os
import time
from pathlib import Path

# Configuration for the automated live server
LIVE_PORT = 8008
LIVE_SERVER_URL = f"http://127.0.0.1:{LIVE_PORT}"
TEST_SECRET = "test-secret-for-automated-fuzzing"

# Standardize the secret for the test process too so tokens can be verified
import decnet.web.auth
decnet.web.auth.SECRET_KEY = TEST_SECRET

# Create a valid token for an admin-like user
TEST_TOKEN = create_access_token({"uuid": "00000000-0000-0000-0000-000000000001"})

@st.hook
def before_call(context, case, *args):
    # Logged-in admin for all requests
    case.headers = case.headers or {}
    case.headers["Authorization"] = f"Bearer {TEST_TOKEN}"

def wait_for_port(port, timeout=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(('127.0.0.1', port)) == 0:
                return True
        time.sleep(0.2)
    return False

def start_automated_server():
    # Use the current venv's uvicorn
    uvicorn_bin = "uvicorn" if os.name != "nt" else "uvicorn.exe"
    uvicorn_path = str(Path(sys.executable).parent / uvicorn_bin)

    # Force developer and contract test modes for the sub-process
    env = os.environ.copy()
    env["DECNET_DEVELOPER"] = "true"
    env["DECNET_CONTRACT_TEST"] = "true"
    env["DECNET_JWT_SECRET"] = TEST_SECRET

    proc = subprocess.Popen(
        [uvicorn_path, "decnet.web.api:app", "--host", "127.0.0.1", "--port", str(LIVE_PORT), "--log-level", "error"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Register cleanup
    atexit.register(proc.terminate)

    if not wait_for_port(LIVE_PORT):
        proc.terminate()
        raise RuntimeError(f"Automated server failed to start on port {LIVE_PORT}")

    return proc

# Stir up the server!
_server_proc = start_automated_server()

# Now Schemathesis can pull the schema from the real network port
schema = st.openapi.from_url(f"{LIVE_SERVER_URL}/openapi.json")

@pytest.mark.fuzz
@st.pytest.parametrize(api=schema)
@settings(max_examples=3000, deadline=None, verbosity=Verbosity.debug)
def test_schema_compliance(case):
    #print(f"\n[Fuzzing] {case.method} {case.path} with query={case.query}")
    case.call_and_validate()
    #print(f"  └─ Success")
