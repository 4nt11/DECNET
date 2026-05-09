"""Tests for GET /api/v1/attackers/export/stix — fleet-wide STIX bundle."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import stix2

from decnet.ttp import attack_stix
from decnet.web.router.attackers.api_export_attackers_stix import (
    api_export_attackers_stix,
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
async def test_empty_fleet_returns_bundle():
    """Zero attackers → valid bundle with just the DECNET org identity."""
    m = _mock_repo()
    with patch("decnet.web.router.attackers.api_export_attackers_stix.repo", m):
        resp = await api_export_attackers_stix(user=_FAKE_USER)
    bundle = json.loads(resp.body)
    assert bundle["type"] == "bundle"


@pytest.mark.asyncio
async def test_single_attacker_baseline_objects():
    """One attacker with no TTPs → 4 objects (org, ip, observed-data, threat-actor)."""
    m = _mock_repo(rows=[_attacker()])
    with patch("decnet.web.router.attackers.api_export_attackers_stix.repo", m):
        resp = await api_export_attackers_stix(user=_FAKE_USER)
    objs = json.loads(resp.body)["objects"]
    types = [o["type"] for o in objs]
    assert types.count("identity") == 1
    assert types.count("ipv4-addr") == 1
    assert types.count("observed-data") == 1
    assert types.count("threat-actor") == 1
    assert len(objs) == 4


@pytest.mark.asyncio
async def test_attack_patterns_deduplicated_across_attackers():
    """Two attackers sharing T1059 → only one attack-pattern SDO in bundle."""
    rows = [_attacker("att-1111", "1.1.1.1"), _attacker("att-2222", "2.2.2.2")]
    rollup = {"technique_id": "T1059", "sub_technique_id": None, "tactic": "TA0002",
              "count": 1, "confidence_max": 0.9}
    ttp_by_attacker = {"att-1111": [rollup], "att-2222": [rollup]}
    m = _mock_repo(rows=rows, ttp_by_attacker=ttp_by_attacker)
    with patch("decnet.web.router.attackers.api_export_attackers_stix.repo", m):
        resp = await api_export_attackers_stix(user=_FAKE_USER)
    objs = json.loads(resp.body)["objects"]
    assert [o for o in objs if o["type"] == "attack-pattern"].__len__() == 1


@pytest.mark.asyncio
async def test_two_attackers_two_threat_actors():
    """Two distinct attacker rows → two distinct threat-actor SDOs."""
    rows = [_attacker("att-1111", "1.1.1.1"), _attacker("att-2222", "2.2.2.2")]
    m = _mock_repo(rows=rows)
    with patch("decnet.web.router.attackers.api_export_attackers_stix.repo", m):
        resp = await api_export_attackers_stix(user=_FAKE_USER)
    objs = json.loads(resp.body)["objects"]
    assert len([o for o in objs if o["type"] == "threat-actor"]) == 2


@pytest.mark.asyncio
async def test_commands_included_in_fleet():
    """Commands from the inline commands field are emitted as process SCOs."""
    row = _attacker()
    row["commands"] = [
        {"command_text": "whoami", "ts": "2026-01-10T00:00:00"},
        {"command_text": "id", "ts": "2026-01-10T00:01:00"},
    ]
    m = _mock_repo(rows=[row])
    with patch("decnet.web.router.attackers.api_export_attackers_stix.repo", m):
        resp = await api_export_attackers_stix(user=_FAKE_USER)
    objs = json.loads(resp.body)["objects"]
    processes = [o for o in objs if o["type"] == "process"]
    assert len(processes) == 2
    assert {p["command_line"] for p in processes} == {"whoami", "id"}


@pytest.mark.asyncio
async def test_stix2_round_trip_validation():
    """Fleet bundle must parse cleanly with stix2."""
    rows = [_attacker("att-1111", "1.1.1.1"), _attacker("att-2222", "2.2.2.2")]
    rollup = {"technique_id": "T1059", "sub_technique_id": None, "tactic": "TA0002",
              "count": 2, "confidence_max": 0.85}
    m = _mock_repo(rows=rows, ttp_by_attacker={"att-1111": [rollup]})
    with patch("decnet.web.router.attackers.api_export_attackers_stix.repo", m):
        resp = await api_export_attackers_stix(user=_FAKE_USER)
    parsed = stix2.parse(resp.body, allow_custom=True)
    assert parsed.type == "bundle"


@pytest.mark.asyncio
async def test_response_headers():
    m = _mock_repo()
    with patch("decnet.web.router.attackers.api_export_attackers_stix.repo", m):
        resp = await api_export_attackers_stix(user=_FAKE_USER)
    assert resp.media_type == "application/json"
    assert "decnet-fleet-" in resp.headers["content-disposition"]
    assert ".stix.json" in resp.headers["content-disposition"]
