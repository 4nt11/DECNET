"""Unit tests for decnet/ttp/stix_custom.py custom STIX types.

Verifies that:
- DecnetActorFingerprintExt instantiates, serialises, and round-trips.
- XDecnetBehaveProfile instantiates, serialises, and round-trips.
- Both types survive a full bundle parse with allow_custom=True.
- FINGERPRINT_EXT_DEF is a valid ExtensionDefinition SDO.
"""
from __future__ import annotations

import json
import uuid as _uuid

import pytest
import stix2

from decnet.ttp.stix_custom import (
    ACTOR_FINGERPRINT_EXT_ID,
    FINGERPRINT_EXT_DEF,
    DecnetActorFingerprintExt,
    XDecnetBehaveProfile,
)

_NS = _uuid.UUID("b5d2c3a1-8f4e-4d1b-9a6c-0e7f5b3d2c1a")
_ORG_ID = f"identity--{_uuid.uuid5(_NS, 'decnet-honeypot')}"


def test_ext_id_is_extension_definition():
    assert ACTOR_FINGERPRINT_EXT_ID.startswith("extension-definition--")


def test_fingerprint_ext_def_valid():
    assert FINGERPRINT_EXT_DEF.id == ACTOR_FINGERPRINT_EXT_ID
    assert FINGERPRINT_EXT_DEF.type == "extension-definition"
    assert "property-extension" in FINGERPRINT_EXT_DEF.extension_types


def test_decnet_actor_fingerprint_ext_roundtrip():
    net = {"os_guess": "Linux 4.x", "hop_distance": 7, "retransmit_count": 1}
    fp = {"ja3_hashes": ["abc123"], "kex_order_raw": ["curve25519-sha256"]}
    ext = DecnetActorFingerprintExt(
        extension_type="property-extension",
        network_behavior=net,
        protocol_fingerprints=fp,
    )
    raw = json.loads(ext.serialize())
    assert raw["extension_type"] == "property-extension"
    assert raw["network_behavior"]["os_guess"] == "Linux 4.x"
    assert raw["protocol_fingerprints"]["ja3_hashes"] == ["abc123"]


def test_decnet_actor_fingerprint_ext_partial():
    ext = DecnetActorFingerprintExt(
        extension_type="property-extension",
        network_behavior={"behavior_class": "scanning"},
    )
    raw = json.loads(ext.serialize())
    assert "protocol_fingerprints" not in raw


def test_x_decnet_behave_profile_roundtrip():
    obs = [
        {
            "primitive": "motor.input_modality",
            "value": "typed",
            "confidence": 0.9,
            "window": {"start_ts": 1.0, "end_ts": 2.0},
            "source": "ssh",
            "evidence_ref": "shard:dky/ssh/2026-01-01.jsonl#1",
        }
    ]
    profile = XDecnetBehaveProfile(  # type: ignore[call-arg]
        id=f"x-decnet-behave-profile--{_uuid.uuid5(_NS, 'attacker-1')}",
        created_by_ref=_ORG_ID,
        schema_version=1,
        kd_digraph_simhash="deadbeef12345678",
        observations=obs,
    )
    raw = json.loads(profile.serialize())
    assert raw["type"] == "x-decnet-behave-profile"
    assert raw["schema_version"] == 1
    assert raw["kd_digraph_simhash"] == "deadbeef12345678"
    assert len(raw["observations"]) == 1
    assert raw["observations"][0]["primitive"] == "motor.input_modality"


def test_x_decnet_behave_profile_stix2_parse_roundtrip():
    profile = XDecnetBehaveProfile(  # type: ignore[call-arg]
        id=f"x-decnet-behave-profile--{_uuid.uuid5(_NS, 'attacker-2')}",
        created_by_ref=_ORG_ID,
        schema_version=1,
        kd_digraph_simhash=None,
        observations=[],
    )
    parsed = stix2.parse(profile.serialize(), allow_custom=True)
    assert type(parsed).__name__ == "XDecnetBehaveProfile"


def test_threat_actor_with_extension_bundle_roundtrip():
    """Full bundle round-trip: ThreatActor with ext + profile SDO + ext-def SDO."""
    net = {"os_guess": "FreeBSD", "hop_distance": 3}
    fp = {"hassh_hashes": ["h1h2h3"]}
    ext = DecnetActorFingerprintExt(
        extension_type="property-extension",
        network_behavior=net,
        protocol_fingerprints=fp,
    )
    profile_id = f"x-decnet-behave-profile--{_uuid.uuid5(_NS, 'attacker-rt')}"
    obs = [
        {
            "primitive": "cognitive.exploration_style",
            "value": "targeted",
            "confidence": 0.85,
            "window": {"start_ts": 100.0, "end_ts": 200.0},
            "source": "ssh",
            "evidence_ref": "shard:dky/ssh/2026-01-02.jsonl#42",
        }
    ]
    profile = XDecnetBehaveProfile(  # type: ignore[call-arg]
        id=profile_id,
        created_by_ref=_ORG_ID,
        schema_version=1,
        kd_digraph_simhash="cafebabe00000000",
        observations=obs,
    )
    ta = stix2.ThreatActor(
        id=f"threat-actor--{_uuid.uuid5(_NS, 'attacker-rt')}",
        name="DECNET-test-actor",
        threat_actor_types=["unknown"],
        created_by_ref=_ORG_ID,
        extensions={ACTOR_FINGERPRINT_EXT_ID: ext},
        x_decnet_behave_profile_ref=profile_id,
        allow_custom=True,
    )
    bundle = stix2.Bundle(
        objects=[FINGERPRINT_EXT_DEF, profile, ta], allow_custom=True
    )
    parsed = stix2.parse(bundle.serialize(), allow_custom=True)

    parsed_ta = next(o for o in parsed.objects if o.type == "threat-actor")
    parsed_ext = parsed_ta.extensions[ACTOR_FINGERPRINT_EXT_ID]
    parsed_profile = next(
        o for o in parsed.objects if o.type == "x-decnet-behave-profile"
    )

    # Extension is typed, not a bare dict
    assert type(parsed_ext).__name__ == "DecnetActorFingerprintExt"
    assert parsed_ext.network_behavior["os_guess"] == "FreeBSD"
    assert parsed_ext.protocol_fingerprints["hassh_hashes"] == ["h1h2h3"]

    # Profile SDO is typed and lossless
    assert type(parsed_profile).__name__ == "XDecnetBehaveProfile"
    assert parsed_profile.kd_digraph_simhash == "cafebabe00000000"
    assert parsed_profile.observations[0]["primitive"] == "cognitive.exploration_style"

    # Ref survives
    assert parsed_ta.x_decnet_behave_profile_ref == profile_id
