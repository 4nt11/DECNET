"""GET /api/v1/ttp/rules returns the live rule catalogue.

Pins the runtime fix that replaced the contract-phase ``return []``
with a real ``RuleStore.load_compiled()`` walk. Each row must carry
the YAML rule's ``rule_id`` / ``rule_version`` / ``name`` /
``description`` plus the operational state stamped by the store
(default ``enabled`` for rules that never had a state set).
"""
from __future__ import annotations

from typing import Any

import httpx
import pytest

from .conftest import RULES, hdr


@pytest.mark.asyncio
async def test_rules_catalogue_returns_loaded_yaml_rules(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    res = await client.get(RULES, headers=hdr(auth_token))
    assert res.status_code == 200, res.text
    body: list[dict[str, Any]] = res.json()
    # The repo ships 58 rules in `rules/ttp/`. The CLI test rig may
    # run with a different store backend; we only require that the
    # catalogue is non-empty and that every advertised row has the
    # documented shape.
    assert isinstance(body, list)
    assert len(body) > 0
    rule_ids = {row["rule_id"] for row in body}
    # Spot-check a couple of well-known rule IDs from the v0 pack.
    assert "R0001" in rule_ids
    assert "R0014" in rule_ids


@pytest.mark.asyncio
async def test_rules_catalogue_row_shape(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    res = await client.get(RULES, headers=hdr(auth_token))
    body: list[dict[str, Any]] = res.json()
    row = next(r for r in body if r["rule_id"] == "R0014")
    assert row["rule_version"] >= 1
    assert isinstance(row["name"], str) and row["name"]
    assert isinstance(row["description"], str)
    assert row["state"] == "enabled"  # default until an admin mutates


@pytest.mark.asyncio
async def test_rules_catalogue_sorted_by_rule_id(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    """Stable order — UI tooling and golden snapshots depend on it."""
    res = await client.get(RULES, headers=hdr(auth_token))
    body: list[dict[str, Any]] = res.json()
    ids = [row["rule_id"] for row in body]
    assert ids == sorted(ids)
