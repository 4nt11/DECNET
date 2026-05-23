# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 6 — GET /api/v1/attackers/{uuid}/attribution.

Pins the contract: 401 unauth, 404 unknown attacker, 200 with empty
``primitives`` for an attacker with no stub identity yet, 200 with
populated ``primitives`` after the attribution worker has run.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from decnet.web.dependencies import repo as _repo

_V1 = "/api/v1/attackers"
_OTHER_UUID = "00000000-0000-0000-0000-000000000099"


async def _seed_attacker(ip: str = "10.0.0.5") -> str:
    return await _repo.upsert_attacker({
        "ip": ip,
        "first_seen": datetime.now(timezone.utc),
        "last_seen": datetime.now(timezone.utc),
    })


@pytest.mark.asyncio
async def test_attribution_unauthenticated(
    client: httpx.AsyncClient,
) -> None:
    """No Bearer token → 401, full stop."""
    auid = await _seed_attacker()
    resp = await client.get(f"{_V1}/{auid}/attribution")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_attribution_unknown_attacker_returns_404(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    resp = await client.get(
        f"{_V1}/{_OTHER_UUID}/attribution",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_attribution_no_stub_yet(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    """Attacker exists but the attribution worker hasn't seen any
    observations yet → 200 with identity_uuid=None and empty list."""
    auid = await _seed_attacker(ip="10.0.0.10")
    resp = await client.get(
        f"{_V1}/{auid}/attribution",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["identity_uuid"] is None
    assert body["primitives"] == []


@pytest.mark.asyncio
async def test_attribution_returns_state_rows(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    """After stub identity + state writes, the endpoint surfaces
    every per-primitive row, primitive-ordered."""
    auid = await _seed_attacker(ip="10.0.0.11")
    iuid = await _repo.ensure_stub_identity_for_attacker(auid)
    assert iuid is not None
    for primitive, state in [
        ("motor.input_modality", "stable"),
        ("cognitive.feedback_loop_engagement", "drifting"),
    ]:
        await _repo.upsert_attribution_state({
            "identity_uuid": iuid,
            "primitive": primitive,
            "current_value": "x",
            "state": state,
            "confidence": 0.85,
            "observation_count": 5,
            "last_change_ts": 1714000000.0,
            "last_observation_ts": 1714000000.0,
        })

    resp = await client.get(
        f"{_V1}/{auid}/attribution",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["identity_uuid"] == iuid
    primitives = body["primitives"]
    assert len(primitives) == 2
    # Primitive-ordered.
    assert [p["primitive"] for p in primitives] == [
        "cognitive.feedback_loop_engagement",
        "motor.input_modality",
    ]
    # Schema sanity.
    expected_keys = {
        "primitive", "current_value", "state", "confidence",
        "observation_count", "last_change_ts", "last_observation_ts",
    }
    for p in primitives:
        assert set(p.keys()) == expected_keys
    states = {p["primitive"]: p["state"] for p in primitives}
    assert states["motor.input_modality"] == "stable"
    assert states["cognitive.feedback_loop_engagement"] == "drifting"
