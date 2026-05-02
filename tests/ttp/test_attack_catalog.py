"""ATT&CK technique-name catalogue covers every ID emitted by the rule pack.

A rule author who adds a new technique to ``rules/ttp/`` must also
update ``decnet/ttp/attack_catalog.py`` in the same commit. Without
this test the UI silently falls back to the bare ID for unknown
techniques.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from decnet.ttp.attack_catalog import TECHNIQUE_NAMES, technique_name


_RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "ttp"


def _all_technique_ids_in_rule_pack() -> set[str]:
    ids: set[str] = set()
    for path in sorted(_RULES_DIR.glob("R*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for emit in doc.get("emits", []) or []:
            tid = emit.get("technique_id")
            if isinstance(tid, str) and tid:
                ids.add(tid)
            sub = emit.get("sub_technique_id")
            if isinstance(sub, str) and sub:
                ids.add(sub)
    return ids


def test_every_rule_pack_technique_has_a_catalogue_entry() -> None:
    rule_ids = _all_technique_ids_in_rule_pack()
    missing = sorted(rule_ids - TECHNIQUE_NAMES.keys())
    assert not missing, (
        "rules/ttp/ emits techniques absent from "
        "decnet/ttp/attack_catalog.py: " + ", ".join(missing)
    )


def test_technique_name_returns_canonical_label() -> None:
    assert technique_name("T1595") == "Active Scanning"
    assert technique_name("T1595.002") == "Active Scanning: Vulnerability Scanning"


def test_technique_name_unknown_id_returns_none() -> None:
    assert technique_name("T9999") is None
    assert technique_name(None) is None
    assert technique_name("") is None


def test_catalogue_entries_are_non_empty_strings() -> None:
    for tid, name in TECHNIQUE_NAMES.items():
        assert isinstance(name, str) and name.strip(), (
            f"empty / non-string name for {tid!r}: {name!r}"
        )
