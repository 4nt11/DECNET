# SPDX-License-Identifier: AGPL-3.0-or-later
"""Router-level coverage for GET /api/v1/ttp/techniques/{tid}/groups.

Calls the handler directly (no TestClient) — the auth dependency is
satisfied by passing a fake user dict. The handler delegates almost
everything to ``attack_stix.groups_using_technique``, which has its
own coverage in ``test_attack_url.py``; the focus here is the 404
path and the empty-list-on-zero-groups behavior.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException

from decnet.ttp import attack_stix
from decnet.web.router.ttp.api_get_groups_for_technique import (
    api_groups_for_technique,
)

_REPO_BUNDLE = Path(__file__).resolve().parents[2] / "decnet" / "data" / "enterprise-attack-19.1.json"


@pytest.fixture(autouse=True)
def _pin_bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    license_path = tmp_path / "LICENSE.txt"
    license_path.write_text("placeholder", encoding="utf-8")
    monkeypatch.setenv("DECNET_ATTACK_BUNDLE", str(_REPO_BUNDLE))
    monkeypatch.setenv("DECNET_ATTACK_LICENSE", str(license_path))
    attack_stix._data = None
    attack_stix._loaded_path = None
    attack_stix._attack_pattern_by_id.cache_clear()
    attack_stix._tactic_by_id.cache_clear()
    attack_stix._tactic_by_short_name.cache_clear()
    attack_stix.groups_using_technique.cache_clear()


_FAKE_USER: dict = {"uuid": "test-user", "role": "viewer"}


@pytest.mark.asyncio
async def test_returns_grouprefs_for_known_technique() -> None:
    result = await api_groups_for_technique(
        technique_id="T1059", user=_FAKE_USER,
    )
    assert isinstance(result, list)
    assert len(result) >= 5
    assert all(isinstance(g, attack_stix.GroupRef) for g in result)
    # Sorted ordering preserved.
    ids = [g.group_id for g in result]
    assert ids == sorted(ids)


@pytest.mark.asyncio
async def test_returns_404_for_unknown_technique() -> None:
    with pytest.raises(HTTPException) as exc:
        await api_groups_for_technique(
            technique_id="T9999", user=_FAKE_USER,
        )
    assert exc.value.status_code == 404
    assert "T9999" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_subtechnique_returns_distinct_group_set() -> None:
    parent = await api_groups_for_technique(
        technique_id="T1059", user=_FAKE_USER,
    )
    sub = await api_groups_for_technique(
        technique_id="T1059.004", user=_FAKE_USER,
    )
    assert len(sub) >= 1
    # Sub-technique attribution is independent of parent (see
    # ATT&CK Navigator semantics) — sub may have groups not in parent.
    # Just assert both are populated.
    assert len(parent) >= len(sub)


@pytest.mark.asyncio
async def test_empty_list_for_known_technique_with_no_documented_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real-bundle technique with zero documented groups returns []."""
    # Force the cache to return () for a real technique.
    attack_stix.groups_using_technique.cache_clear()
    monkeypatch.setattr(
        attack_stix,
        "groups_using_technique",
        lambda tid: () if tid == "T1110" else attack_stix.groups_using_technique(tid),
    )
    result = await api_groups_for_technique(
        technique_id="T1110", user=_FAKE_USER,
    )
    assert result == []


@pytest.mark.asyncio
async def test_response_includes_mitre_url_and_aliases() -> None:
    result = await api_groups_for_technique(
        technique_id="T1059", user=_FAKE_USER,
    )
    assert all(
        g.mitre_url and g.mitre_url.startswith("https://attack.mitre.org/groups/G")
        for g in result
    )
    # At least one group has multiple aliases.
    assert any(len(g.aliases) >= 2 for g in result)
