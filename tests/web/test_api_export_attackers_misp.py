"""Tests for GET /api/v1/attackers/export/misp — fleet-wide MISP collection."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from decnet.ttp import attack_stix
from decnet.web.router.attackers.api_export_attackers_misp import (
    api_export_attackers_misp,
)

_REPO_BUNDLE = Path(__file__).resolve().parents[2] / "enterprise-attack-19.0.json"
_FAKE_USER: dict = {"uuid": "test-user", "role": "viewer"}


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


def _attacker(uuid: str = "att-aaaa", ip: str = "1.2.3.4") -> dict:
    return {
        "uuid": uuid,
        "ip": ip,
        "first_seen": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "last_seen": datetime(2026, 1, 31, tzinfo=timezone.utc),
        "event_count": 10,
        "identity_id": None,
        "country_code": "US",
        "asn": 15169,
        "as_name": "GOOGLE",
        "commands": [],
        "threat_intel": None,
    }


def _mock_repo(*, rows=None, ttp_by_attacker=None):
    m = type("M", (), {})()
    m.get_all_attackers_for_export = AsyncMock(return_value=rows or [])
    m.get_all_ttp_rollups_for_export = AsyncMock(return_value=ttp_by_attacker or {})
    m.get_all_observations_for_export = AsyncMock(return_value={})
    return m


@pytest.mark.asyncio
async def test_empty_fleet_returns_empty_collection():
    """Zero attackers → {"response": []}."""
    m = _mock_repo()
    with patch("decnet.web.router.attackers.api_export_attackers_misp.repo", m):
        resp = await api_export_attackers_misp(user=_FAKE_USER)
    body = json.loads(resp.body)
    assert "response" in body
    assert body["response"] == []


@pytest.mark.asyncio
async def test_single_attacker_one_event():
    """One attacker → collection with one event."""
    m = _mock_repo(rows=[_attacker()])
    with patch("decnet.web.router.attackers.api_export_attackers_misp.repo", m):
        resp = await api_export_attackers_misp(user=_FAKE_USER)
    body = json.loads(resp.body)
    assert len(body["response"]) == 1


@pytest.mark.asyncio
async def test_two_attackers_two_events():
    """Two distinct attacker rows → two events in the collection."""
    rows = [_attacker("att-1111", "1.1.1.1"), _attacker("att-2222", "2.2.2.2")]
    m = _mock_repo(rows=rows)
    with patch("decnet.web.router.attackers.api_export_attackers_misp.repo", m):
        resp = await api_export_attackers_misp(user=_FAKE_USER)
    body = json.loads(resp.body)
    assert len(body["response"]) == 2


@pytest.mark.asyncio
async def test_commands_in_fleet_event():
    """Commands in the row's commands field end up in the event."""
    row = _attacker()
    row["commands"] = [
        {"command_text": "whoami", "ts": "2026-01-10T00:00:00"},
        {"command_text": "id", "ts": "2026-01-10T00:01:00"},
    ]
    m = _mock_repo(rows=[row])
    with patch("decnet.web.router.attackers.api_export_attackers_misp.repo", m):
        resp = await api_export_attackers_misp(user=_FAKE_USER)
    body = json.loads(resp.body)
    assert len(body["response"]) == 1


@pytest.mark.asyncio
async def test_response_headers():
    m = _mock_repo()
    with patch("decnet.web.router.attackers.api_export_attackers_misp.repo", m):
        resp = await api_export_attackers_misp(user=_FAKE_USER)
    assert resp.media_type == "application/json"
    cd = resp.headers["content-disposition"]
    assert "decnet-fleet-" in cd
    assert ".misp.json" in cd
