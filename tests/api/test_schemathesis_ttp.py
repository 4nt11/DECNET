"""Schemathesis contract tests scoped to the TTP Tagging API surface.

E.3.17 of ``development/TTP_TAGGING.md``. The full ``test_schemathesis``
suite fuzzes every endpoint with ``max_examples=3000`` — slow and
overkill when iterating on TTP-routes-only changes (E.3.13–E.3.16).
This file filters by the OpenAPI ``tags=["TTP Tagging"]`` annotation
the eight TTP routes carry, runs against the same live uvicorn
subprocess the wider suite spins up, and applies the same check
battery so a 4xx-shape regression on a TTP route fails here without
waiting on the rest of the API.

Routes covered (all decorated ``tags=["TTP Tagging"]``):

* ``GET    /api/v1/ttp/techniques``
* ``GET    /api/v1/ttp/by-identity/{identity_uuid}``
* ``GET    /api/v1/ttp/by-attacker/{attacker_uuid}``
* ``GET    /api/v1/ttp/by-campaign/{campaign_uuid}``
* ``GET    /api/v1/ttp/by-session/{session_id}``
* ``GET    /api/v1/ttp/rules``
* ``POST   /api/v1/ttp/rules/{rule_id}/state``
* ``DELETE /api/v1/ttp/rules/{rule_id}/state``
* ``GET    /api/v1/ttp/export/navigator``
* ``GET    /api/v1/ttp/export/navigator/identity/{identity_uuid}``
"""
from __future__ import annotations

import os
import pytest

_QUICK = os.getenv("SCHEMA_QUICK") == "1"
import schemathesis as st
from hypothesis import HealthCheck, Verbosity, settings

from tests.api.test_schemathesis import (
    ALL_CHECKS,
    AUTH_CHECKS,
    LIVE_SERVER_URL,
    before_call as _shared_before_call,  # noqa: F401  (registers @st.hook)
)

# Reuse the schema fetched against the same uvicorn subprocess started
# by ``test_schemathesis``. Filtering by tag keeps the TTP suite a
# fast, focused contract gate without re-spinning the server.
TTP_SCHEMA = st.openapi.from_url(
    f"{LIVE_SERVER_URL}/openapi.json",
).include(tag="TTP Tagging")


@pytest.mark.fuzz
@TTP_SCHEMA.parametrize()
@settings(
    max_examples=100 if _QUICK else 400,
    deadline=None,
    verbosity=Verbosity.normal,
    suppress_health_check=[
        HealthCheck.filter_too_much,
        HealthCheck.too_slow,
        HealthCheck.data_too_large,
    ],
)
def test_ttp_schema_compliance(case):
    """Per-TTP-route schema compliance — valid + invalid inputs."""
    case.call_and_validate(checks=ALL_CHECKS)


@pytest.mark.fuzz
@TTP_SCHEMA.parametrize()
@settings(
    max_examples=100 if _QUICK else 120,
    deadline=None,
    verbosity=Verbosity.normal,
    suppress_health_check=[
        HealthCheck.filter_too_much,
        HealthCheck.too_slow,
    ],
)
def test_ttp_auth_enforcement(case):
    """Every TTP route rejects requests without a Bearer token (401).

    The mutation endpoints additionally require ``admin`` (server-side
    ``require_admin``); the authless probe doesn't distinguish 401 vs
    403 here — the ``ignored_auth`` check just asserts that an absent
    token never lands the request inside the handler with a usable
    identity.
    """
    case.headers = {
        k: v for k, v in (case.headers or {}).items()
        if k.lower() != "authorization"
    }
    case.call_and_validate(checks=AUTH_CHECKS)
