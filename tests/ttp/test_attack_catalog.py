"""Every technique ID emitted by ``rules/ttp/`` must resolve in the loaded ATT&CK STIX bundle.

The shim in :mod:`decnet.ttp.attack_catalog` now reads names from the
official MITRE ATT&CK Enterprise STIX bundle (loader at
:mod:`decnet.ttp.attack_stix`). This test enforces the same invariant
that the old hand-maintained dict did — a rule author who adds a
technique that isn't in the pinned ATT&CK release gets a loud failure
at deploy time rather than a silent UI fallback.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from decnet.ttp import attack_stix
from decnet.ttp.attack_catalog import technique_name

_RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "ttp"
_REPO_BUNDLE = Path(__file__).resolve().parents[2] / "enterprise-attack-19.0.json"


@pytest.fixture(scope="module", autouse=True)
def _use_repo_bundle(monkeypatch_module: pytest.MonkeyPatch) -> None:
    """Pin DECNET_ATTACK_BUNDLE to the in-repo copy for hermetic tests."""
    monkeypatch_module.setenv("DECNET_ATTACK_BUNDLE", str(_REPO_BUNDLE))
    # Reset the lazy singleton so the env var is honored.
    attack_stix._data = None
    attack_stix._loaded_path = None
    attack_stix._attack_pattern_by_id.cache_clear()
    attack_stix._tactic_by_id.cache_clear()
    attack_stix._tactic_by_short_name.cache_clear()


@pytest.fixture(scope="module")
def monkeypatch_module() -> pytest.MonkeyPatch:
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


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


def test_every_rule_pack_technique_resolves_in_bundle() -> None:
    rule_ids = _all_technique_ids_in_rule_pack()
    missing = sorted(t for t in rule_ids if not attack_stix.technique_exists(t))
    assert not missing, (
        f"rules/ttp/ emits techniques absent from ATT&CK Enterprise "
        f"v{attack_stix.ATTACK_BUNDLE_VERSION}: {missing}"
    )


def test_technique_name_returns_canonical_label() -> None:
    assert technique_name("T1595") == "Active Scanning"
    assert technique_name("T1595.002") == "Active Scanning: Vulnerability Scanning"


def test_technique_name_unknown_id_returns_none() -> None:
    assert technique_name("T9999") is None
    assert technique_name(None) is None
    assert technique_name("") is None


def test_subtechnique_format_matches_legacy() -> None:
    # Spot-check the historical "Parent: Child" rendering.
    assert technique_name("T1059.004") == (
        "Command and Scripting Interpreter: Unix Shell"
    )
    assert technique_name("T1110.001") == "Brute Force: Password Guessing"


def test_assert_known_technique_ids_raises_on_missing() -> None:
    with pytest.raises(attack_stix.AttackBundleError) as exc:
        attack_stix.assert_known_technique_ids(
            ["T1059", "T9999"], source="test_assert"
        )
    assert "T9999" in str(exc.value)
    assert "T1059" not in str(exc.value)


def test_tactic_lookup_by_id_and_short_name() -> None:
    assert attack_stix.tactic_name("TA0001") == "Initial Access"
    assert attack_stix.tactic_name("initial-access") == "Initial Access"
    assert attack_stix.tactic_id_for_short_name("initial-access") == "TA0001"
    assert attack_stix.tactic_exists("TA0001")
    assert not attack_stix.tactic_exists("TA9999")


def test_sha256_mismatch_refuses_to_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bogus = tmp_path / "enterprise-attack-19.0.json"
    bogus.write_bytes(b'{"type":"bundle","id":"bundle--x","objects":[]}')
    monkeypatch.setenv("DECNET_ATTACK_BUNDLE", str(bogus))
    with pytest.raises(attack_stix.AttackBundleError) as exc:
        attack_stix._verify_sha256(bogus)
    assert "does not match" in str(exc.value)
