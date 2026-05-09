"""Integration tests for the x_decnet_* ThreatActor extensions in stix_export.py.

Covers:
- Skinny attacker (no behavior, no identity, no observations) → no extension block,
  no profile SDO, no extension-definition SDO.
- Attacker with behavior → extension block with network_behavior populated.
- Attacker with identity fingerprints → protocol_fingerprints group.
- Attacker with BEHAVE observations → x-decnet-behave-profile SDO in bundle,
  x_decnet_behave_profile_ref on ThreatActor, extension-definition SDO present.
- kd_digraph_simhash hex-encoded correctly (bytes and base64 inputs).
- Full inter-DECNET round-trip: stix2.parse(bundle, allow_custom=True) yields
  typed extension objects, not bare dicts.
"""
from __future__ import annotations

import base64
import json
import uuid as _uuid
from datetime import datetime, timezone

import pytest
import stix2

from decnet.ttp.stix_custom import (
    ACTOR_FINGERPRINT_EXT_ID,
    DecnetActorFingerprintExt,
    XDecnetBehaveProfile,
)
from decnet.ttp.stix_export import build_attacker_bundle

_NS = _uuid.UUID("b5d2c3a1-8f4e-4d1b-9a6c-0e7f5b3d2c1a")


def _attacker(uid: str = "att-aaaabbbbccccdddd") -> dict:
    return {
        "uuid": uid,
        "ip": "1.2.3.4",
        "first_seen": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "last_seen": datetime(2026, 1, 31, tzinfo=timezone.utc),
        "event_count": 100,
        "country_code": "US",
        "asn": 15169,
        "as_name": "GOOGLE",
    }


def _behavior() -> dict:
    return {
        "os_guess": "Linux 4.x",
        "hop_distance": 7,
        "tcp_fingerprint": json.dumps({
            "window": 65535, "wscale": 6, "mss": 1460,
            "options_sig": "MSTNNT", "has_sack": True, "ipid_class": "zero",
        }),
        "kex_order_raw": json.dumps(["curve25519-sha256", "ecdh-sha2-nistp256"]),
        "ssh_client_banners": json.dumps(["SSH-2.0-OpenSSH_8.9"]),
        "retransmit_count": 3,
        "behavior_class": "brute_force",
        "beacon_interval_s": 60.0,
        "beacon_jitter_pct": 0.05,
        "timing_stats": json.dumps({"mean": 1.2, "stdev": 0.3}),
        "phase_sequence": json.dumps({"recon_end": "2026-01-10T00:00:00"}),
        "tool_guesses": json.dumps(["hydra"]),
    }


def _identity(uid: str = "ident-1111222233334444") -> dict:
    return {
        "uuid": uid,
        "ja3_hashes": json.dumps(["abc123def456"]),
        "hassh_hashes": json.dumps(["hashhash01"]),
        "tls_cert_sha256": json.dumps(["a" * 64]),
        "payload_simhashes": json.dumps(["deadbeef12345678"]),
        "c2_endpoints": json.dumps([{"host": "bad.example.com", "port": 4444}]),
        "kd_digraph_simhash": None,
    }


def _obs() -> list[dict]:
    return [
        {
            "primitive": "motor.input_modality",
            "value": "typed",
            "confidence": 0.9,
            "window": {"start_ts": 1000.0, "end_ts": 2000.0},
            "source": "ssh",
            "evidence_ref": "shard:dky/ssh/2026-01-01.jsonl#1",
        },
        {
            "primitive": "cognitive.exploration_style",
            "value": "targeted",
            "confidence": 0.8,
            "window": {"start_ts": 2000.0, "end_ts": 3000.0},
            "source": "ssh",
            "evidence_ref": "shard:dky/ssh/2026-01-01.jsonl#2",
        },
    ]


def _get_ta(bundle: stix2.Bundle) -> stix2.ThreatActor:
    return next(o for o in bundle.objects if o.type == "threat-actor")


def test_skinny_attacker_no_extension():
    """No behavior, no identity, no observations → no extension block."""
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=None, identity=None, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=None,
    )
    ta = _get_ta(bundle)
    assert not getattr(ta, "extensions", None)
    profile_sdos = [o for o in bundle.objects if o.type == "x-decnet-behave-profile"]
    assert len(profile_sdos) == 0
    ext_def_sdos = [o for o in bundle.objects if o.type == "extension-definition"]
    assert len(ext_def_sdos) == 0


def test_behavior_produces_network_behavior_group():
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=_behavior(), identity=None, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=None,
    )
    ta = _get_ta(bundle)
    assert ta.extensions, "expected extension block"
    ext = ta.extensions[ACTOR_FINGERPRINT_EXT_ID]
    nb = ext.network_behavior
    assert nb["os_guess"] == "Linux 4.x"
    assert nb["hop_distance"] == 7
    assert nb["retransmit_count"] == 3
    assert nb["behavior_class"] == "brute_force"
    assert nb["tcp_fingerprint"]["window"] == 65535
    assert nb["timing_stats"]["mean"] == pytest.approx(1.2)
    assert "hydra" in nb["tool_guesses"]


def test_behavior_produces_protocol_fingerprints_from_behavior():
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=_behavior(), identity=None, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=None,
    )
    ta = _get_ta(bundle)
    ext = ta.extensions[ACTOR_FINGERPRINT_EXT_ID]
    fp = ext.protocol_fingerprints
    assert fp["kex_order_raw"] == ["curve25519-sha256", "ecdh-sha2-nistp256"]
    assert fp["ssh_client_banners"] == ["SSH-2.0-OpenSSH_8.9"]


def test_identity_fingerprints_in_protocol_group():
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=None, identity=_identity(), intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=None,
    )
    ta = _get_ta(bundle)
    ext = ta.extensions[ACTOR_FINGERPRINT_EXT_ID]
    fp = ext.protocol_fingerprints
    assert fp["ja3_hashes"] == ["abc123def456"]
    assert fp["hassh_hashes"] == ["hashhash01"]
    assert fp["tls_cert_sha256"] == ["a" * 64]
    c2 = fp["c2_endpoints"]
    assert isinstance(c2, list) and c2[0]["host"] == "bad.example.com"


def test_no_legacy_flat_x_decnet_hash_properties():
    """Dropped: x_decnet_ja3_hashes / x_decnet_hassh_hashes / x_decnet_c2_endpoints."""
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=_behavior(), identity=_identity(), intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=None,
    )
    ta = _get_ta(bundle)
    for old_prop in ("x_decnet_ja3_hashes", "x_decnet_hassh_hashes", "x_decnet_c2_endpoints"):
        assert not hasattr(ta, old_prop), f"legacy property {old_prop!r} should not exist"


def test_observations_produce_behave_profile_sdo():
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=None, identity=None, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=_obs(),
    )
    ta = _get_ta(bundle)
    assert hasattr(ta, "x_decnet_behave_profile_ref")
    profile_sdos = [o for o in bundle.objects if o.type == "x-decnet-behave-profile"]
    assert len(profile_sdos) == 1
    profile = profile_sdos[0]
    assert profile.id == ta.x_decnet_behave_profile_ref
    assert len(profile.observations) == 2
    assert profile.observations[0]["primitive"] == "motor.input_modality"
    assert profile.observations[0]["confidence"] == pytest.approx(0.9)
    assert profile.observations[0]["window"]["start_ts"] == pytest.approx(1000.0)


def test_observations_include_extension_def_sdo():
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=None, identity=None, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=_obs(),
    )
    ext_defs = [o for o in bundle.objects if o.type == "extension-definition"]
    assert len(ext_defs) == 1
    assert ext_defs[0].id == ACTOR_FINGERPRINT_EXT_ID


def test_kd_digraph_simhash_bytes_input():
    ident = _identity()
    ident["kd_digraph_simhash"] = b"\xde\xad\xbe\xef\x12\x34\x56\x78"
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=None, identity=ident, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=[_obs()[0]],
    )
    profile = next(o for o in bundle.objects if o.type == "x-decnet-behave-profile")
    assert profile.kd_digraph_simhash == "deadbeef12345678"


def test_kd_digraph_simhash_base64_input():
    raw = b"\xca\xfe\xba\xbe\x00\x00\x00\x00"
    ident = _identity()
    ident["kd_digraph_simhash"] = base64.b64encode(raw).decode()
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=None, identity=ident, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=[_obs()[0]],
    )
    profile = next(o for o in bundle.objects if o.type == "x-decnet-behave-profile")
    assert profile.kd_digraph_simhash == raw.hex()


def _fp_bounties() -> list[dict]:
    return [
        {
            "payload": {
                "fingerprint_type": "jarm",
                "hash": "2ad2ad16d2ad2ad00042d42d000000f93d17e5fba64fc1c6f4cb080b9a5cf1e",
                "target_ip": "1.2.3.4",
                "target_port": "443",
            }
        },
        {
            "payload": {
                "fingerprint_type": "http_quirks",
                "order_hash": "abc123",
                "order": ["Host", "User-Agent", "Accept"],
                "casing_hash": "def456",
                "casing_category": "title_case",
                "stable_count": 3,
                "tool_guess": "curl",
            }
        },
        {
            "payload": {
                "fingerprint_type": "jarm",
                "hash": "2ad2ad16d2ad2ad00042d42d000000f93d17e5fba64fc1c6f4cb080b9a5cf1e",
            }
        },
    ]


def test_fingerprint_bounties_jarm_in_protocol_fingerprints():
    """JARM hashes from bounties appear deduplicated in protocol_fingerprints."""
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=None, identity=None, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=None,
        fingerprint_bounties=_fp_bounties(),
    )
    ta = _get_ta(bundle)
    assert ta.extensions, "expected extension block with fingerprint bounties"
    ext = ta.extensions[ACTOR_FINGERPRINT_EXT_ID]
    fp = ext.protocol_fingerprints
    assert "jarm_hashes" in fp
    assert len(fp["jarm_hashes"]) == 1, "duplicate JARM hash must be collapsed"
    assert "http_quirks" in fp
    assert fp["http_quirks"][0]["tool_guess"] == "curl"
    assert fp["http_quirks"][0]["order"] == ["Host", "User-Agent", "Accept"]


def test_fingerprint_bounties_empty_produces_no_extension():
    """Empty fingerprint bounties with no other signal → no extension block."""
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=None, identity=None, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=None,
        fingerprint_bounties=[],
    )
    ta = _get_ta(bundle)
    assert not getattr(ta, "extensions", None)


def test_behave_profile_has_characterizes_relationship():
    """When behave_profile is present the bundle contains a 'characterizes' Relationship."""
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=None, identity=None, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=_obs(),
    )
    ta = _get_ta(bundle)
    profile = next(o for o in bundle.objects if o.type == "x-decnet-behave-profile")
    rels = [o for o in bundle.objects if o.type == "relationship"
            and o.relationship_type == "characterizes"]
    assert len(rels) == 1
    rel = rels[0]
    assert rel.source_ref == profile.id
    assert rel.target_ref == ta.id


def test_no_behave_profile_no_characterizes_relationship():
    """Skinny attacker with no observations → no 'characterizes' relationship."""
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=None, identity=None, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=None,
    )
    rels = [o for o in bundle.objects if o.type == "relationship"
            and o.relationship_type == "characterizes"]
    assert len(rels) == 0


def test_inter_decnet_round_trip():
    """Primary fidelity: stix2.parse restores typed objects, not bare dicts."""
    ident = _identity()
    ident["kd_digraph_simhash"] = b"\xde\xad\xbe\xef\x12\x34\x56\x78"
    bundle = build_attacker_bundle(
        attacker=_attacker(),
        behavior=_behavior(), identity=ident, intel=None,
        technique_rollup=[], raw_tags=[], artifacts=[],
        smtp_targets=[], observations=_obs(),
    )
    parsed = stix2.parse(bundle.serialize(pretty=True, indent=2), allow_custom=True)

    parsed_ta = next(o for o in parsed.objects if o.type == "threat-actor")
    assert ACTOR_FINGERPRINT_EXT_ID in parsed_ta.extensions
    parsed_ext = parsed_ta.extensions[ACTOR_FINGERPRINT_EXT_ID]
    assert type(parsed_ext).__name__ == "DecnetActorFingerprintExt"
    assert parsed_ext.network_behavior["os_guess"] == "Linux 4.x"
    assert parsed_ext.protocol_fingerprints["ja3_hashes"] == ["abc123def456"]

    parsed_profile = next(o for o in parsed.objects if o.type == "x-decnet-behave-profile")
    assert type(parsed_profile).__name__ == "XDecnetBehaveProfile"
    assert parsed_profile.kd_digraph_simhash == "deadbeef12345678"
    primitives = {obs["primitive"] for obs in parsed_profile.observations}
    assert "motor.input_modality" in primitives
    assert "cognitive.exploration_style" in primitives
