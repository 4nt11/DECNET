"""Schemathesis contract tests for the swarm-controller API
(``decnet.web.swarm_api``).

Uses schemathesis's ASGI transport so we don't have to stand up uvicorn
with mTLS. The controller's transport-layer mTLS is out of scope here —
we're validating schema/behavioral conformance of its routes.
"""
from __future__ import annotations

import os

# Must be set BEFORE importing the swarm_api module — the repo factory
# reads DECNET_DB_TYPE at import time via dependencies.py.
os.environ["DECNET_DB_TYPE"] = "sqlite"
os.environ["DECNET_MODE"] = "master"
os.environ.setdefault("DECNET_JWT_SECRET", "schemathesis-swarm-secret-32chars-min-pad")

import pytest
import schemathesis as st
from schemathesis.checks import not_a_server_error
from schemathesis.specs.openapi.checks import (
    status_code_conformance,
    content_type_conformance,
    response_headers_conformance,
    response_schema_conformance,
)
from hypothesis import settings, HealthCheck

from decnet.web import swarm_api as _swarm_api

# OpenAPI is disabled by default on the controller (internal surface).
# FastAPI only wires /openapi.json during __init__; toggling the attribute
# post-hoc is a no-op, so register the route explicitly here.
_swarm_api.app.openapi_url = "/openapi.json"

@_swarm_api.app.get("/openapi.json", include_in_schema=False)
async def _openapi_contract_test():
    return _swarm_api.app.openapi()


SCHEMA = st.openapi.from_asgi("/openapi.json", _swarm_api.app)

pytestmark = pytest.mark.fuzz

CHECKS = (
    not_a_server_error,
    status_code_conformance,
    content_type_conformance,
    response_headers_conformance,
    response_schema_conformance,
)


@pytest.mark.fuzz
@SCHEMA.parametrize()
@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[
        HealthCheck.filter_too_much,
        HealthCheck.too_slow,
        HealthCheck.data_too_large,
    ],
)
def test_swarm_schema_compliance(case):
    """Fuzz the swarm-controller routes against its OpenAPI schema."""
    case.call_and_validate(checks=CHECKS)
