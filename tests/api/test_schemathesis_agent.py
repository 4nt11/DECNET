"""Schemathesis contract tests for the worker-side agent API
(``decnet.agent.app``).

Uses schemathesis's ASGI transport. The agent's real security is
transport-layer mTLS — out of scope here; we're validating schema
conformance only.

The executor and heartbeat modules are stubbed so fuzzed requests don't
actually deploy containers, tear down services, or self-destruct the host.
"""
from __future__ import annotations

import pytest
import schemathesis as st
from schemathesis.specs.openapi.checks import (
    status_code_conformance,
    content_type_conformance,
    response_headers_conformance,
    response_schema_conformance,
)
from hypothesis import settings, HealthCheck

from decnet.agent import app as _agent_app_mod
from decnet.agent import executor as _exec
from decnet.agent import heartbeat as _heartbeat


# ---------------------------------------------------------------------------
# Safety stubs — fuzzer must never touch real docker / systemd / disk.
# Applied via autouse fixture (NOT module-level assignment) so the stubs
# don't leak into tests/swarm/test_agent_app.py which imports the same
# executor module.
# ---------------------------------------------------------------------------

async def _noop_deploy(*a, **kw):
    return {"status": "stub"}

async def _noop_teardown(*a, **kw):
    return {"status": "stub"}

async def _noop_self_destruct(*a, **kw):
    return {"status": "stub"}

async def _noop_status(*a, **kw):
    return {"deckies": [], "running": False, "deployed": False}


@pytest.fixture(autouse=True)
def _stub_agent_executor(monkeypatch):
    monkeypatch.setattr(_exec, "deploy", _noop_deploy)
    monkeypatch.setattr(_exec, "teardown", _noop_teardown)
    monkeypatch.setattr(_exec, "self_destruct", _noop_self_destruct)
    monkeypatch.setattr(_exec, "status", _noop_status)
    async def _noop_async(*a, **kw):
        return None
    monkeypatch.setattr(_heartbeat, "start", lambda *a, **kw: None)
    # stop() is awaited by the lifespan — must be a coroutine function.
    monkeypatch.setattr(_heartbeat, "stop", _noop_async)
    yield

# OpenAPI is disabled on the worker by default (narrow attack surface).
# FastAPI only wires up /openapi.json during __init__; changing the attribute
# after the fact is a no-op, so register the route explicitly for the fuzzer.
_agent_app_mod.app.openapi_url = "/openapi.json"

@_agent_app_mod.app.get("/openapi.json", include_in_schema=False)
async def _openapi_contract_test():
    return _agent_app_mod.app.openapi()


SCHEMA = st.openapi.from_asgi("/openapi.json", _agent_app_mod.app)

pytestmark = pytest.mark.fuzz

CHECKS = (
    # Intentionally omit `not_a_server_error`: /mutate returns a documented
    # 501 Not Implemented, which that check flags as a failure regardless of
    # whether the status is in the schema. `status_code_conformance` already
    # catches *undocumented* 5xx responses.
    status_code_conformance,
    content_type_conformance,
    response_headers_conformance,
    response_schema_conformance,
)


@pytest.mark.fuzz
@SCHEMA.parametrize()
@settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[
        HealthCheck.filter_too_much,
        HealthCheck.too_slow,
        HealthCheck.data_too_large,
    ],
)
def test_agent_schema_compliance(case):
    """Fuzz the agent routes against the worker OpenAPI schema."""
    case.call_and_validate(checks=CHECKS)
