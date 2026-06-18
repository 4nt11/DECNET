# SPDX-License-Identifier: AGPL-3.0-or-later
"""``attack_stix.mitre_url_for`` and ``groups_using_technique`` happy/sad paths.

These are the bundle-derived helpers Phase 3 wires into the
TTPTag column and the new groups endpoint. Tests pin against the
in-repo bundle (DECNET_ATTACK_BUNDLE) so they run hermetically and
the spot-check assertions stay tolerant of minor across-version
re-namings.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from decnet.ttp import attack_stix

_REPO_BUNDLE = Path(__file__).resolve().parents[2] / "decnet" / "data" / "enterprise-attack-19.1.json"


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


def test_mitre_url_for_top_level_technique() -> None:
    assert (
        attack_stix.mitre_url_for("T1059")
        == "https://attack.mitre.org/techniques/T1059"
    )


def test_mitre_url_for_subtechnique() -> None:
    assert (
        attack_stix.mitre_url_for("T1059.004")
        == "https://attack.mitre.org/techniques/T1059/004"
    )


@pytest.mark.parametrize("bad", [None, "", "T9999", "not-a-technique"])
def test_mitre_url_for_returns_none_for_unknown(bad: str | None) -> None:
    assert attack_stix.mitre_url_for(bad) is None


def test_groups_using_technique_returns_grouprefs() -> None:
    groups = attack_stix.groups_using_technique("T1059")
    assert len(groups) >= 5
    sample = groups[0]
    assert isinstance(sample, attack_stix.GroupRef)
    assert sample.group_id.startswith("G")
    assert sample.name
    assert sample.mitre_url and sample.mitre_url.startswith(
        "https://attack.mitre.org/groups/G"
    )


def test_groups_using_technique_is_sorted_by_group_id() -> None:
    groups = attack_stix.groups_using_technique("T1059")
    ids = [g.group_id for g in groups]
    assert ids == sorted(ids), f"groups not sorted by group_id: {ids}"


def test_groups_using_technique_aliases_populated_for_at_least_one() -> None:
    groups = attack_stix.groups_using_technique("T1059")
    # Some MITRE groups have rich alias lists; assert at least one
    # group surfaces aliases. Bundle-version-tolerant: we don't pin
    # the alias text, just that the field is populated somewhere.
    assert any(len(g.aliases) >= 2 for g in groups)


def test_groups_using_technique_subtechnique_distinct_from_parent() -> None:
    """T1059.004 (Unix Shell) has fewer attributed groups than the abstract T1059.

    Sub-technique semantics: ATT&CK tracks group attribution
    independently for sub-techniques. We do NOT auto-union with the
    parent (matches Navigator behavior).
    """
    parent = attack_stix.groups_using_technique("T1059")
    sub = attack_stix.groups_using_technique("T1059.004")
    assert len(sub) >= 1
    assert len(sub) <= len(parent)


@pytest.mark.parametrize("bad", ["", "T9999", "not-a-technique"])
def test_groups_using_technique_unknown_returns_empty(bad: str) -> None:
    assert attack_stix.groups_using_technique(bad) == ()


def test_groupref_is_frozen_and_hashable() -> None:
    g = attack_stix.GroupRef(
        group_id="G0001",
        name="Test",
        aliases=("Test",),
        mitre_url=None,
    )
    with pytest.raises(Exception):
        g.name = "other"  # type: ignore[misc]
    # Hashable so we can put GroupRef in a set if a caller wants.
    assert hash(g)
