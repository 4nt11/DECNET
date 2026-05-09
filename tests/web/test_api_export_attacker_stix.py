"""Tests for GET /api/v1/attackers/{uuid}/export/stix.

Tests call the handler directly (no TestClient). The attack_stix bundle
is pinned to the repo's enterprise-attack-19.0.json so Sighting and
Relationship target_refs are real MITRE STIX IDs.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import stix2

from decnet.ttp import attack_stix
from decnet.web.router.attackers.api_export_attacker_stix import (
    api_export_attacker_stix,
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


def _tag(technique_id: str, ts: datetime | None = None) -> dict:
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
        "created_at": ts or datetime(2026, 1, 15, tzinfo=timezone.utc),
    }


def _technique_row(technique_id: str) -> dict:
    return {
        "technique_id": technique_id,
        "sub_technique_id": None,
        "tactic": "TA0006",
        "count": 3,
        "confidence_max": 0.85,
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


def _mock_repo(*, attacker=None, identity=None, intel=None,
               rollup=None, tags=None, artifacts=None, smtp=None, commands=None):
    m = type("M", (), {})()
    m.get_attacker_by_uuid = AsyncMock(return_value=attacker or _attacker())
    m.get_attacker_behavior = AsyncMock(return_value={})
    m.get_identity_by_uuid = AsyncMock(return_value=identity)
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
    return m


@pytest.mark.asyncio
async def test_404_on_unknown_attacker():
    m = _mock_repo()
    m.get_attacker_by_uuid = AsyncMock(return_value=None)
    with patch("decnet.web.router.attackers.api_export_attacker_stix.repo", m):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            await api_export_attacker_stix("no-such-uuid", user=_FAKE_USER)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_skinny_attacker_returns_4_baseline_objects():
    """No TTPs, no artifacts, no intel — bundle has 4 objects."""
    m = _mock_repo()
    with patch("decnet.web.router.attackers.api_export_attacker_stix.repo", m):
        resp = await api_export_attacker_stix("att-aaaabbbbccccdddd", user=_FAKE_USER)
    bundle = json.loads(resp.body)
    assert bundle["type"] == "bundle"
    # spec_version lives on each contained SDO, not the bundle envelope
    assert all(o.get("spec_version") == "2.1" for o in bundle["objects"] if "created" in o)
    types = [o["type"] for o in bundle["objects"]]
    assert types.count("identity") == 1
    assert types.count("ipv4-addr") == 1
    assert types.count("observed-data") == 1
    assert types.count("threat-actor") == 1
    assert len(bundle["objects"]) == 4


@pytest.mark.asyncio
async def test_full_bundle_object_count():
    """Seeded attacker: 2 techniques, 3 tags, 1 artifact, 1 smtp, intel."""
    tags = [_tag("T1110"), _tag("T1110"), _tag("T1059")]
    m = _mock_repo(
        rollup=["T1110", "T1059"],
        tags=tags,
        artifacts=[_artifact()],
        smtp=[_smtp_target()],
        intel=_intel(),
    )
    with patch("decnet.web.router.attackers.api_export_attacker_stix.repo", m):
        resp = await api_export_attacker_stix("att-aaaabbbbccccdddd", user=_FAKE_USER)
    objs = json.loads(resp.body)["objects"]
    types = [o["type"] for o in objs]
    # 1 identity + 1 ipv4-addr + 1 observed-data(ip) + 1 threat-actor
    # + 2 attack-patterns + 2 relationships
    # + 3 sightings
    # + 1 file + 1 observed-data(file)
    # + 1 domain-name + 1 observed-data(smtp)
    # + 1 note
    assert types.count("identity") == 1
    assert types.count("ipv4-addr") == 1
    assert types.count("threat-actor") == 1
    assert types.count("attack-pattern") == 2
    assert types.count("relationship") == 2
    assert types.count("sighting") == 3
    assert types.count("file") == 1
    assert types.count("domain-name") == 1
    assert types.count("note") == 1
    assert len([t for t in types if t == "observed-data"]) == 3


@pytest.mark.asyncio
async def test_stix2_round_trip_validation():
    """Bundle must parse cleanly with stix2 (strict=True)."""
    tags = [_tag("T1059")]
    m = _mock_repo(rollup=["T1059"], tags=tags, intel=_intel())
    with patch("decnet.web.router.attackers.api_export_attacker_stix.repo", m):
        resp = await api_export_attacker_stix("att-aaaabbbbccccdddd", user=_FAKE_USER)
    parsed = stix2.parse(resp.body, allow_custom=True)
    assert parsed.type == "bundle"


@pytest.mark.asyncio
async def test_attack_pattern_target_refs_match_mitre_bundle():
    """Every relationship.target_ref is a real MITRE attack-pattern ID."""
    tags = [_tag("T1059"), _tag("T1110")]
    m = _mock_repo(rollup=["T1059", "T1110"], tags=tags)
    with patch("decnet.web.router.attackers.api_export_attacker_stix.repo", m):
        resp = await api_export_attacker_stix("att-aaaabbbbccccdddd", user=_FAKE_USER)
    objs = json.loads(resp.body)["objects"]
    rels = [o for o in objs if o["type"] == "relationship" and o["relationship_type"] == "uses"]
    target_refs = {r["target_ref"] for r in rels}
    t1059_id = attack_stix._attack_pattern_by_id("T1059")["id"]
    t1110_id = attack_stix._attack_pattern_by_id("T1110")["id"]
    assert t1059_id in target_refs
    assert t1110_id in target_refs


@pytest.mark.asyncio
async def test_sighting_count_equals_tag_count():
    """One Sighting per raw ttp_tag row; each carries count=1."""
    tags = [_tag("T1059"), _tag("T1059"), _tag("T1059")]
    m = _mock_repo(rollup=["T1059"], tags=tags)
    with patch("decnet.web.router.attackers.api_export_attacker_stix.repo", m):
        resp = await api_export_attacker_stix("att-aaaabbbbccccdddd", user=_FAKE_USER)
    objs = json.loads(resp.body)["objects"]
    sightings = [o for o in objs if o["type"] == "sighting"]
    assert len(sightings) == 3
    assert all(s["count"] == 1 for s in sightings)


@pytest.mark.asyncio
async def test_commands_emit_process_scos():
    """Deduped commands produce one process SCO + observed-data pair each."""
    cmds = ["whoami", "cat /etc/passwd", "whoami"]  # duplicate → 2 unique
    m = _mock_repo(commands=cmds)
    with patch("decnet.web.router.attackers.api_export_attacker_stix.repo", m):
        resp = await api_export_attacker_stix("att-aaaabbbbccccdddd", user=_FAKE_USER)
    objs = json.loads(resp.body)["objects"]
    processes = [o for o in objs if o["type"] == "process"]
    assert len(processes) == 2
    cmd_lines = {p["command_line"] for p in processes}
    assert cmd_lines == {"whoami", "cat /etc/passwd"}
    # Each unique command emits a Sighting back to the threat-actor (no TTP tags here)
    sightings = [o for o in objs if o["type"] == "sighting"]
    assert len(sightings) == 2
    ta_id = next(o["id"] for o in objs if o["type"] == "threat-actor")
    assert all(s["sighting_of_ref"] == ta_id for s in sightings)


@pytest.mark.asyncio
async def test_response_headers():
    m = _mock_repo()
    with patch("decnet.web.router.attackers.api_export_attacker_stix.repo", m):
        resp = await api_export_attacker_stix("att-aaaabbbbccccdddd", user=_FAKE_USER)
    assert resp.media_type == "application/json"
    assert ".stix.json" in resp.headers["content-disposition"]
