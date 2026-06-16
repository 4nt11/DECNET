# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for GET /api/v1/attackers/{uuid}/export/misp."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from decnet.ttp import attack_stix
from decnet.web.router.attackers.api_export_attacker_misp import (
    api_export_attacker_misp,
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


def _attacker(uuid: str = "att-aaaabbbbccccdddd") -> dict:
    return {
        "uuid": uuid,
        "ip": "1.2.3.4",
        "first_seen": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "last_seen": datetime(2026, 1, 31, tzinfo=timezone.utc),
        "event_count": 100,
        "identity_id": None,
        "country_code": "US",
        "asn": 15169,
        "as_name": "GOOGLE",
    }


def _tag(technique_id: str) -> dict:
    return {
        "uuid": f"tag-{technique_id}",
        "attacker_uuid": "att-aaaabbbbccccdddd",
        "technique_id": technique_id,
        "sub_technique_id": None,
        "tactic": "TA0006",
        "confidence": 0.85,
        "rule_id": "R0001",
        "rule_version": 1,
        "evidence": {},
        "created_at": datetime(2026, 1, 15, tzinfo=timezone.utc),
    }


def _artifact(sha256: str = "a" * 64) -> dict:
    return {
        "timestamp": datetime(2026, 1, 10, tzinfo=timezone.utc),
        "fields": json.dumps({"sha256": sha256, "filename": "payload.sh"}),
    }


def _smtp_target() -> dict:
    return {
        "domain": "victim.example.com",
        "count": 5,
        "first_seen": datetime(2026, 1, 5, tzinfo=timezone.utc),
        "last_seen": datetime(2026, 1, 20, tzinfo=timezone.utc),
    }


def _intel() -> dict:
    return {
        "aggregate_verdict": "malicious",
        "abuseipdb_score": 95,
        "greynoise_classification": "malicious",
        "greynoise_tags": json.dumps(["ssh_bruteforcer"]),
        "feodo_listed": False,
        "threatfox_listed": False,
    }


def _mock_repo(*, attacker=None, intel=None, rollup=None, tags=None,
               artifacts=None, smtp=None, commands=None):
    m = type("M", (), {})()
    m.get_attacker_by_uuid = AsyncMock(return_value=attacker or _attacker())
    m.get_attacker_behavior = AsyncMock(return_value={})
    m.get_identity_by_uuid = AsyncMock(return_value=None)
    m.get_attacker_intel_by_uuid = AsyncMock(return_value=intel)
    from decnet.web.db.models.ttp import IdentityTechniqueRow
    m.list_techniques_by_attacker = AsyncMock(
        return_value=[
            IdentityTechniqueRow(
                technique_id=t, technique_name=None,
                sub_technique_id=None, sub_technique_name=None,
                tactic="TA0006", count=1, confidence_max=0.8,
                first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
                last_seen=datetime(2026, 1, 31, tzinfo=timezone.utc),
                mitre_url=None,
            )
            for t in (rollup or [])
        ]
    )
    m.list_ttp_tags_by_attacker = AsyncMock(return_value=tags or [])
    m.get_attacker_artifacts = AsyncMock(return_value=artifacts or [])
    m.list_smtp_targets = AsyncMock(return_value=smtp or [])
    m.list_attacker_commands_deduped = AsyncMock(return_value=commands or [])
    m.list_observations_by_attacker = AsyncMock(return_value=[])
    m.get_fingerprint_bounties_by_ip = AsyncMock(return_value=[])
    return m


@pytest.mark.asyncio
async def test_404_on_unknown_attacker():
    m = _mock_repo()
    m.get_attacker_by_uuid = AsyncMock(return_value=None)
    with patch("decnet.web.router.attackers.api_export_attacker_misp.repo", m):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            await api_export_attacker_misp("no-such-uuid", user=_FAKE_USER)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_skinny_attacker_returns_misp_event():
    """No TTPs, no artifacts — response is valid MISP event JSON."""
    m = _mock_repo()
    with patch("decnet.web.router.attackers.api_export_attacker_misp.repo", m):
        resp = await api_export_attacker_misp("att-aaaabbbbccccdddd", user=_FAKE_USER)
    event = json.loads(resp.body)
    # Must be a MISP event dict with an Attribute list
    assert "Attribute" in event or "info" in event


@pytest.mark.asyncio
async def test_ip_attribute_present():
    """Attacker IP appears as an ip-src or ip-dst attribute."""
    m = _mock_repo()
    with patch("decnet.web.router.attackers.api_export_attacker_misp.repo", m):
        resp = await api_export_attacker_misp("att-aaaabbbbccccdddd", user=_FAKE_USER)
    event = json.loads(resp.body)
    attrs = event.get("Attribute", [])
    ip_attrs = [a for a in attrs if a.get("value") == "1.2.3.4"]
    assert len(ip_attrs) >= 1


@pytest.mark.asyncio
async def test_file_hash_attribute_present():
    """A captured artifact's SHA-256 appears in the MISP event."""
    m = _mock_repo(artifacts=[_artifact("b" * 64)])
    with patch("decnet.web.router.attackers.api_export_attacker_misp.repo", m):
        resp = await api_export_attacker_misp("att-aaaabbbbccccdddd", user=_FAKE_USER)
    event = json.loads(resp.body)
    all_attrs = event.get("Attribute", [])
    # Also check inside Objects
    for obj in event.get("Object", []):
        all_attrs.extend(obj.get("Attribute", []))
    hash_attrs = [a for a in all_attrs if ("b" * 64) in str(a.get("value", ""))]
    assert len(hash_attrs) >= 1


@pytest.mark.asyncio
async def test_domain_attribute_present():
    """An SMTP target domain appears in the MISP event."""
    m = _mock_repo(smtp=[_smtp_target()])
    with patch("decnet.web.router.attackers.api_export_attacker_misp.repo", m):
        resp = await api_export_attacker_misp("att-aaaabbbbccccdddd", user=_FAKE_USER)
    event = json.loads(resp.body)
    all_attrs = event.get("Attribute", [])
    for obj in event.get("Object", []):
        all_attrs.extend(obj.get("Attribute", []))
    domain_attrs = [
        a for a in all_attrs if "victim.example.com" in str(a.get("value", ""))
    ]
    assert len(domain_attrs) >= 1


@pytest.mark.asyncio
async def test_mitre_galaxy_present_when_technique_tagged():
    """A MITRE ATT&CK galaxy cluster appears when a technique is tagged."""
    m = _mock_repo(rollup=["T1059"], tags=[_tag("T1059")])
    with patch("decnet.web.router.attackers.api_export_attacker_misp.repo", m):
        resp = await api_export_attacker_misp("att-aaaabbbbccccdddd", user=_FAKE_USER)
    event = json.loads(resp.body)
    galaxies = event.get("Galaxy", [])
    # misp-stix maps attack-pattern SDOs to "STIX 2.1 Attack Pattern" galaxies
    attack_pattern_galaxy = any(
        "attack pattern" in str(g.get("name", "")).lower() for g in galaxies
    )
    assert attack_pattern_galaxy


@pytest.mark.asyncio
async def test_response_headers():
    m = _mock_repo()
    with patch("decnet.web.router.attackers.api_export_attacker_misp.repo", m):
        resp = await api_export_attacker_misp("att-aaaabbbbccccdddd", user=_FAKE_USER)
    assert resp.media_type == "application/json"
    assert ".misp.json" in resp.headers["content-disposition"]


@pytest.mark.asyncio
async def test_pymisp_round_trip():
    """Event round-trips through pymisp.MISPEvent.from_dict without error."""
    import pymisp
    m = _mock_repo(rollup=["T1059"], tags=[_tag("T1059")], intel=_intel())
    with patch("decnet.web.router.attackers.api_export_attacker_misp.repo", m):
        resp = await api_export_attacker_misp("att-aaaabbbbccccdddd", user=_FAKE_USER)
    raw = json.loads(resp.body)
    e = pymisp.MISPEvent()
    e.from_dict(**raw)
    assert e.info
