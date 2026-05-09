"""STIX 2.1 bundle builder for a DECNET attacker observation.

Pure function — no I/O. The caller (router) does all DB reads and
passes dicts; this module assembles the STIX bundle.

SDO/SRO mapping
---------------
DECNET data                → STIX type
-----------                  ---------
Producer (DECNET)          → identity (org, deterministic ID)
attacker.ip                → ipv4-addr SCO
first/last seen + count    → observed-data SDO
AttackerIdentity or IP     → threat-actor SDO
Per-technique rollup       → attack-pattern SDO + relationship(uses) SRO
Per ttp_tag row            → sighting SRO
ObservedAttachment / Log   → file SCO + observed-data SDO
SmtpTarget                 → domain-name SCO + observed-data SDO
AttackerIntel verdict      → note SDO

Attack-pattern SDOs carry the canonical MITRE STIX IDs pulled from the
loaded enterprise bundle so the objects are deduplicated against the
public ATT&CK bundle by any consumer that already has it.
"""
from __future__ import annotations

import json
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

import stix2

from decnet.ttp import attack_stix

# Deterministic DECNET org identity ID — stable across all bundles this
# instance produces. Consumers can correlate across exports.
_NS = _uuid.UUID("b5d2c3a1-8f4e-4d1b-9a6c-0e7f5b3d2c1a")
_DECNET_ORG_STIX_ID = f"identity--{_uuid.uuid5(_NS, 'decnet-honeypot')}"


def _aware(dt: datetime | str | None) -> datetime | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _decnet_org() -> stix2.Identity:
    return stix2.Identity(
        id=_DECNET_ORG_STIX_ID,
        name="DECNET",
        identity_class="organization",
        description="DECNET honeypot platform — automated threat observation",
    )


def _threat_actor(
    attacker: dict[str, Any],
    identity: dict[str, Any] | None,
    created_by: str,
) -> stix2.ThreatActor:
    if identity:
        name = f"DECNET-identity-{identity['uuid'][:8]}"
    else:
        name = f"DECNET-attacker-{attacker['uuid'][:8]}"
    kwargs: dict[str, Any] = dict(
        id=f"threat-actor--{_uuid.uuid5(_NS, attacker['uuid'])}",
        name=name,
        threat_actor_types=["unknown"],
        created_by_ref=created_by,
        allow_custom=True,
    )
    if attacker.get("country_code"):
        kwargs["x_decnet_country_code"] = attacker["country_code"]
    if attacker.get("asn"):
        kwargs["x_decnet_asn"] = attacker["asn"]
    if attacker.get("as_name"):
        kwargs["x_decnet_as_name"] = attacker["as_name"]
    if identity:
        if identity.get("ja3_hashes"):
            kwargs["x_decnet_ja3_hashes"] = identity["ja3_hashes"]
        if identity.get("hassh_hashes"):
            kwargs["x_decnet_hassh_hashes"] = identity["hassh_hashes"]
        if identity.get("c2_endpoints"):
            kwargs["x_decnet_c2_endpoints"] = identity["c2_endpoints"]
    return stix2.ThreatActor(**kwargs)


def _attack_pattern_sdo(technique_id: str, created_by: str) -> stix2.AttackPattern | None:
    obj = attack_stix._attack_pattern_by_id(technique_id)
    if obj is None:
        return None
    ext_refs = obj.get("external_references", [])
    mitre_ref = next(
        (r for r in ext_refs if r.get("source_name") == "mitre-attack"), None,
    )
    er_args = [
        stix2.ExternalReference(
            source_name="mitre-attack",
            external_id=mitre_ref["external_id"],
            url=mitre_ref.get("url", ""),
        )
    ] if mitre_ref else []
    return stix2.AttackPattern(
        id=obj["id"],
        name=obj.get("name", technique_id),
        external_references=er_args,
        created_by_ref=created_by,
    )


def _intel_note(
    intel: dict[str, Any],
    ta_id: str,
    created_by: str,
) -> stix2.Note | None:
    verdict = intel.get("aggregate_verdict") or "unknown"
    lines: list[str] = [f"aggregate_verdict: {verdict}"]
    if intel.get("abuseipdb_score") is not None:
        lines.append(f"abuseipdb_score: {intel['abuseipdb_score']}")
    if intel.get("greynoise_classification"):
        tags = intel.get("greynoise_tags") or []
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except Exception:
                tags = []
        lines.append(f"greynoise: {intel['greynoise_classification']} ({', '.join(tags)})")
    if intel.get("feodo_listed"):
        lines.append(f"feodo: {intel.get('feodo_malware_family', 'listed')}")
    if intel.get("threatfox_listed"):
        tt = intel.get("threatfox_threat_types") or []
        if isinstance(tt, str):
            try:
                tt = json.loads(tt)
            except Exception:
                tt = []
        lines.append(f"threatfox: {', '.join(tt) if tt else 'listed'}")
    return stix2.Note(
        abstract="DECNET threat-intel verdict",
        content="\n".join(lines),
        object_refs=[ta_id],
        created_by_ref=created_by,
    )


def build_attacker_bundle(
    attacker: dict[str, Any],
    behavior: dict[str, Any] | None,
    identity: dict[str, Any] | None,
    intel: dict[str, Any] | None,
    technique_rollup: list[dict[str, Any]],
    raw_tags: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    smtp_targets: list[dict[str, Any]],
    commands: list[str] | None = None,
) -> stix2.Bundle:
    """Assemble a STIX 2.1 Bundle for *attacker*.

    All arguments are plain dicts (the shape returned by the DECNET
    repo).  Never raises — unknown/missing data is silently omitted from
    the bundle.
    """
    objs: list[Any] = []

    org = _decnet_org()
    objs.append(org)

    # ── IP observation ──────────────────────────────────────────────
    ipv4 = stix2.IPv4Address(value=attacker["ip"])
    objs.append(ipv4)

    fs = _aware(attacker.get("first_seen"))
    ls = _aware(attacker.get("last_seen"))
    now = datetime.now(timezone.utc)
    ip_obs = stix2.ObservedData(
        first_observed=fs or now,
        last_observed=ls or now,
        number_observed=max(1, attacker.get("event_count") or 1),
        object_refs=[ipv4.id],
        created_by_ref=org.id,
    )
    objs.append(ip_obs)

    # ── Threat actor ─────────────────────────────────────────────────
    ta = _threat_actor(attacker, identity, org.id)
    objs.append(ta)

    # ── ATT&CK — attack-patterns + uses relationships + sightings ───
    # Build per-technique once; sightings reference the same AP STIX ID.
    ap_stix_ids: dict[str, str] = {}  # technique_id → attack-pattern STIX id
    for row in technique_rollup:
        tid = row.get("sub_technique_id") or row.get("technique_id")
        if not tid or tid in ap_stix_ids:
            continue
        ap = _attack_pattern_sdo(tid, org.id)
        if ap is None:
            continue
        ap_stix_ids[tid] = ap.id
        objs.append(ap)
        objs.append(
            stix2.Relationship(
                source_ref=ta.id,
                target_ref=ap.id,
                relationship_type="uses",
                created_by_ref=org.id,
            )
        )

    for tag in raw_tags:
        tid = tag.get("sub_technique_id") or tag.get("technique_id")
        if not tid or tid not in ap_stix_ids:
            continue
        ts = _aware(tag.get("created_at"))
        if ts is None:
            ts = now
        objs.append(
            stix2.Sighting(
                sighting_of_ref=ap_stix_ids[tid],
                first_seen=ts,
                last_seen=ts,
                count=1,
                where_sighted_refs=[org.id],
                observed_data_refs=[ip_obs.id],
                created_by_ref=org.id,
            )
        )

    # ── Artifacts (file_captured log rows) ──────────────────────────
    for art in artifacts:
        fields = art.get("fields") or {}
        if isinstance(fields, str):
            try:
                fields = json.loads(fields)
            except Exception:
                fields = {}
        sha = fields.get("sha256") or fields.get("hash")
        if not sha:
            continue
        file_kwargs: dict[str, Any] = {"hashes": {"SHA-256": sha.lower()}}
        name = fields.get("filename") or fields.get("stored_as")
        if name:
            file_kwargs["name"] = name
        f = stix2.File(**file_kwargs)
        objs.append(f)
        fts = _aware(art.get("timestamp"))
        objs.append(
            stix2.ObservedData(
                first_observed=fts or now,
                last_observed=fts or now,
                number_observed=1,
                object_refs=[f.id],
                created_by_ref=org.id,
            )
        )

    # ── SMTP targets ────────────────────────────────────────────────
    for tgt in smtp_targets:
        domain = tgt.get("domain")
        if not domain:
            continue
        dn = stix2.DomainName(value=domain)
        objs.append(dn)
        s_fs = _aware(tgt.get("first_seen"))
        s_ls = _aware(tgt.get("last_seen"))
        objs.append(
            stix2.ObservedData(
                first_observed=s_fs or now,
                last_observed=s_ls or now,
                number_observed=max(1, tgt.get("count") or 1),
                object_refs=[dn.id],
                created_by_ref=org.id,
            )
        )

    # ── Shell commands (process SCOs + observed-data) ────────────────
    seen_cmds: set[str] = set()
    for cmd_line in commands or []:
        if not cmd_line or cmd_line in seen_cmds:
            continue
        seen_cmds.add(cmd_line)
        proc = stix2.Process(command_line=cmd_line, is_hidden=False)
        objs.append(proc)
        objs.append(
            stix2.ObservedData(
                first_observed=fs or now,
                last_observed=ls or now,
                number_observed=1,
                object_refs=[proc.id],
                created_by_ref=org.id,
            )
        )

    # ── Intel note ───────────────────────────────────────────────────
    if intel:
        note = _intel_note(intel, ta.id, org.id)
        objs.append(note)

    return stix2.Bundle(objects=objs, allow_custom=True)


def build_fleet_bundle(
    rows: list[dict[str, Any]],
    ttp_by_attacker: dict[str, list[dict[str, Any]]],
) -> stix2.Bundle:
    """Assemble a STIX 2.1 Bundle covering all attackers in *rows*.

    Deduplicates by STIX ID — attack-pattern SDOs with the same canonical
    MITRE UUID appear once regardless of how many attackers used the technique.
    Per-tag Sightings, Artifacts, and SMTP targets are omitted in fleet mode
    (too verbose; use the per-attacker endpoint for full fidelity).
    """
    objs_by_id: dict[str, Any] = {}

    for row in rows:
        raw_cmds = row.get("commands") or []
        if isinstance(raw_cmds, str):
            try:
                raw_cmds = json.loads(raw_cmds)
            except Exception:
                raw_cmds = []
        cmds = [
            str(e.get("command_text", "")).strip()
            for e in raw_cmds
            if isinstance(e, dict) and e.get("command_text")
        ]

        intel = row.get("threat_intel")
        bundle = build_attacker_bundle(
            attacker=row,
            behavior=None,
            identity=None,
            intel=intel,
            technique_rollup=ttp_by_attacker.get(row["uuid"], []),
            raw_tags=[],
            artifacts=[],
            smtp_targets=[],
            commands=cmds,
        )
        for obj in bundle.objects:
            objs_by_id[obj.id] = obj

    return stix2.Bundle(objects=list(objs_by_id.values()), allow_custom=True)
