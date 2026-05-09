"""MISP event builder for DECNET attacker data.

Converts a STIX 2.1 Bundle (built by stix_export.build_attacker_bundle /
build_fleet_bundle) into MISP event dicts using the misp-stix library's
ExternalSTIX2toMISPParser.

Pure functions — no I/O. The caller (router) does all DB reads and passes
dicts; this module converts STIX → MISP JSON.

Output shapes
-------------
build_attacker_misp_event  → dict  (single MISP event, ready for import)
build_fleet_misp_collection → dict  ({"response": [event, ...]})
"""
from __future__ import annotations

import json
from typing import Any

from misp_stix_converter import ExternalSTIX2toMISPParser

from decnet.ttp.stix_export import build_attacker_bundle


def _parse_bundle(bundle: Any) -> dict[str, Any]:
    """Run ExternalSTIX2toMISPParser on *bundle* and return the event dict.

    Returns an empty dict if the parser produces no event (e.g. the bundle
    contains only SCOs the parser can't promote to MISP attributes).
    """
    parser = ExternalSTIX2toMISPParser()
    parser.load_stix_bundle(bundle)
    parser.parse_stix_bundle()
    event = parser.misp_events
    if event is None:
        return {}
    return json.loads(event.to_json())


def build_attacker_misp_event(
    attacker: dict[str, Any],
    behavior: dict[str, Any] | None,
    identity: dict[str, Any] | None,
    intel: dict[str, Any] | None,
    technique_rollup: list[dict[str, Any]],
    raw_tags: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    smtp_targets: list[dict[str, Any]],
    commands: list[str] | None = None,
    observations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a MISP event dict for *attacker*.

    All arguments match the signature of stix_export.build_attacker_bundle.
    Never raises — conversion failures produce a minimal event dict.
    """
    bundle = build_attacker_bundle(
        attacker=attacker,
        behavior=behavior,
        identity=identity,
        intel=intel,
        technique_rollup=technique_rollup,
        raw_tags=raw_tags,
        artifacts=artifacts,
        smtp_targets=smtp_targets,
        commands=commands,
        observations=observations,
    )
    return _parse_bundle(bundle)


def build_fleet_misp_collection(
    rows: list[dict[str, Any]],
    ttp_by_attacker: dict[str, list[dict[str, Any]]],
    observations_by_attacker: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Return a MISP collection dict with one event per attacker in *rows*.

    Shape: ``{"response": [event_dict, ...]}``.  Suitable for MISP's
    "Import from MISP JSON" / REST collection endpoint.

    Attackers that produce no parseable MISP event (very unlikely — an
    attacker always has at least an IP) are silently omitted.
    """
    events: list[dict[str, Any]] = []
    obs_map = observations_by_attacker or {}
    for row in rows:
        raw_cmds = row.get("commands") or []
        if isinstance(raw_cmds, str):
            try:
                raw_cmds = json.loads(raw_cmds)
            except Exception:
                raw_cmds = []
        cmds = [
            str(e.get("command_text") or e.get("command") or "").strip()
            for e in raw_cmds
            if isinstance(e, dict) and (e.get("command_text") or e.get("command"))
        ]
        bundle = build_attacker_bundle(
            attacker=row,
            behavior=None,
            identity=None,
            intel=row.get("threat_intel"),
            technique_rollup=ttp_by_attacker.get(row["uuid"], []),
            raw_tags=[],
            artifacts=[],
            smtp_targets=[],
            commands=cmds,
            observations=obs_map.get(row["uuid"]),
        )
        event = _parse_bundle(bundle)
        if event:
            events.append(event)
    return {"response": events}
