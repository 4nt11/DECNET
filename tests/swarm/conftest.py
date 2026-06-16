# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared fixtures for swarm-controller tests.

V4.1.1: every operator endpoint on the swarm controller now requires an
admin-role JWT (``require_admin``) in addition to the loopback/mTLS transport
gate (``require_operator_cert``). The vast majority of swarm-controller tests
exercise *behavior* (enroll bundles, heartbeat pinning, topology resync), not
the auth gate, and predate the JWT requirement.

To keep those tests focused on their subject without threading a real token
through every ``/swarm/enroll`` setup call, this autouse fixture installs a
no-op ``require_admin`` override on the controller app. The override returns a
synthetic admin principal, so the transport gate (``require_operator_cert``)
and the endpoint logic still run exactly as before.

The dedicated auth test (``test_swarm_authz.py``) removes this override inside
its own client context so it exercises the *real* ``require_admin`` against
real JWTs — that file is the single source of truth for the gate's behavior.
"""
from __future__ import annotations

import pytest

from decnet.web.dependencies import require_admin


@pytest.fixture(autouse=True)
def _bypass_swarm_admin_gate():
    """Override require_admin on the swarm-controller app for behavior tests.

    Yields the override callable so a test can detect/remove it if needed.
    """
    from decnet.web.swarm_api import app

    async def _fake_admin() -> dict:
        return {"uuid": "test-admin", "role": "admin", "must_change_password": False}

    app.dependency_overrides[require_admin] = _fake_admin
    yield _fake_admin
    app.dependency_overrides.pop(require_admin, None)
