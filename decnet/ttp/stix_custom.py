# SPDX-License-Identifier: AGPL-3.0-or-later
"""DECNET-defined STIX 2.1 custom extension and object types.

Import this module before parsing any DECNET-produced bundle so the types are
registered with the stix2 library and ``stix2.parse(bundle, allow_custom=True)``
rebuilds them as typed objects rather than opaque dicts.

Classes
-------
DecnetActorFingerprintExt
    ``@CustomExtension`` on ThreatActor — carries ``network_behavior``
    (TCP/TLS/SSH sniffer rollup) and ``protocol_fingerprints`` (hashes +
    raw orderings).
XDecnetBehaveProfile
    ``@CustomObject`` — autonomous STIX SDO carrying the BEHAVE-SHELL
    observation stream for one attacker. Referenced from ThreatActor via
    ``x_decnet_behave_profile_ref``.

Constants
---------
ACTOR_FINGERPRINT_EXT_ID : str
    Fixed ``extension-definition--`` ID for ``DecnetActorFingerprintExt``.
FINGERPRINT_EXT_DEF : stix2.ExtensionDefinition
    Singleton ``extension-definition`` SDO — add to every bundle that uses
    the fingerprint extension.
"""
from __future__ import annotations

import uuid as _uuid

import stix2
from stix2 import CustomExtension, CustomObject, ExtensionDefinition
from stix2 import properties as _P

_NS = _uuid.UUID("b5d2c3a1-8f4e-4d1b-9a6c-0e7f5b3d2c1a")

# Stable ID for the actor fingerprint extension-definition SDO.
ACTOR_FINGERPRINT_EXT_ID: str = (
    f"extension-definition--{_uuid.uuid5(_NS, 'decnet-actor-fingerprint-v1')}"
)

_DECNET_ORG_ID = f"identity--{_uuid.uuid5(_NS, 'decnet-honeypot')}"


@CustomExtension(
    ACTOR_FINGERPRINT_EXT_ID,
    [
        ("extension_type", _P.StringProperty(required=True)),
        ("network_behavior", _P.DictionaryProperty()),
        ("protocol_fingerprints", _P.DictionaryProperty()),
    ],
)
class DecnetActorFingerprintExt:
    """Property extension on ThreatActor.

    ``network_behavior`` keys: os_guess, hop_distance, tcp_fingerprint,
    retransmit_count, timing_stats, phase_sequence, behavior_class,
    beacon_interval_s, beacon_jitter_pct, tool_guesses.

    ``protocol_fingerprints`` keys: ja3_hashes, hassh_hashes, kex_order_raw,
    ssh_client_banners, tls_cert_sha256, payload_simhashes, c2_endpoints.
    """


@CustomObject(
    "x-decnet-behave-profile",
    [
        ("schema_version", _P.IntegerProperty()),
        ("kd_digraph_simhash", _P.StringProperty()),
        ("observations", _P.ListProperty(_P.DictionaryProperty())),
    ],
)
class XDecnetBehaveProfile:
    """BEHAVE-SHELL observation stream for one attacker.

    ``observations`` is a list of BEHAVE envelope dicts with keys:
    primitive, value, confidence, window (start_ts/end_ts), source,
    evidence_ref, identity_ref (optional).

    ``schema_version`` matches ``OBSERVATION_SCHEMA_VERSION`` from
    behave_shell.spec.envelope — bump when the envelope schema changes.

    ``kd_digraph_simhash`` is the 8-byte digraph SimHash from
    AttackerIdentity, hex-encoded. Null when identity has not been clustered.
    """


# Singleton extension-definition SDO.
FINGERPRINT_EXT_DEF: stix2.ExtensionDefinition = ExtensionDefinition(
    id=ACTOR_FINGERPRINT_EXT_ID,
    name="DECNET Actor Fingerprint",
    description=(
        "Extends ThreatActor with DECNET-observed network behavior "
        "(TCP/TLS/SSH stack-level fingerprints, IAT timing, phase sequence) "
        "and BEHAVE-SHELL keystroke-dynamics observation primitives."
    ),
    schema="https://decnet.dev/schemas/actor-fingerprint/v1",
    version="1.0.0",
    extension_types=["property-extension"],
    created_by_ref=_DECNET_ORG_ID,
)
