"""YAML intel-provider mappings reproduce the legacy dicts byte-for-byte.

Snapshot equivalence test: the dicts that used to live in
``decnet/ttp/impl/intel_lifter.py`` are mirrored here as ground
truth. If a future YAML edit drops or adds a category/tag/threat-type
mapping, this test catches it. The same dicts are deleted from the
lifter — they live ONLY here, as the regression net.

Also covers:
* every technique referenced in every YAML resolves in the loaded
  ATT&CK bundle (the loader does this at load; we just confirm it),
* every signal carries a STIX-shaped ``external_reference``,
* the ``mitre_url`` enrichment is present on every emission whose
  technique is in the bundle (i.e. all of them),
* high-score gating (``cat_11``→T1566 only when score≥80) works,
* invalid YAML (unknown technique_id) raises ``AttackBundleError``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
import yaml

from decnet.ttp import attack_stix
from decnet.ttp.data.intel_loader import (
    ProviderMapping,
    clear_cache,
    load_provider_mapping,
)

_REPO_BUNDLE = Path(__file__).resolve().parents[2] / "enterprise-attack-19.0.json"
_DATA_DIR = Path(__file__).resolve().parents[2] / "decnet" / "ttp" / "data" / "intel"


# Ground truth — the legacy dicts from intel_lifter.py before the YAML
# extraction. Edit these only when the mapping intentionally changes,
# and update the corresponding YAML in the same commit.
_ABUSEIPDB_LEGACY: Final[dict[int, frozenset[str]]] = {
    5: frozenset({"T1110"}),
    7: frozenset({"T1566"}),
    9: frozenset({"T1090"}),
    11: frozenset({"T1496", "T1566"}),
    13: frozenset({"T1090"}),
    14: frozenset({"T1046", "T1595"}),
    15: frozenset({"T1190"}),
    16: frozenset({"T1190"}),
    17: frozenset({"T1566"}),
    18: frozenset({"T1110"}),
    19: frozenset({"T1595"}),
    20: frozenset({"T1078"}),
    21: frozenset({"T1190"}),
    22: frozenset({"T1110"}),
    23: frozenset({"T1190"}),
}

_ABUSEIPDB_GATED_LEGACY: Final[dict[int, dict[str, int]]] = {
    11: {"T1566": 80},
}

_GREYNOISE_LEGACY: Final[dict[str, frozenset[str]]] = {
    "tor_exit_node": frozenset({"T1090"}),
    "ssh_bruteforcer": frozenset({"T1110"}),
    "web_crawler": frozenset({"T1595"}),
    "cobalt_strike": frozenset({"T1071", "T1588"}),
    "metasploit": frozenset({"T1071", "T1588"}),
    "sliver": frozenset({"T1071", "T1588"}),
    "havoc": frozenset({"T1071", "T1588"}),
}

_THREATFOX_LEGACY: Final[dict[str, frozenset[str]]] = {
    "botnet_cc": frozenset({"T1071", "T1588"}),
    "payload_delivery": frozenset({"T1105", "T1588"}),
    "payload": frozenset({"T1588"}),
    "cc_skimming": frozenset({"T1056"}),
}


@pytest.fixture(autouse=True)
def _pin_bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    license_path = tmp_path / "LICENSE.txt"
    license_path.write_text("placeholder for tests", encoding="utf-8")
    monkeypatch.setenv("DECNET_ATTACK_BUNDLE", str(_REPO_BUNDLE))
    monkeypatch.setenv("DECNET_ATTACK_LICENSE", str(license_path))
    attack_stix._data = None
    attack_stix._loaded_path = None
    attack_stix._attack_pattern_by_id.cache_clear()
    attack_stix._tactic_by_id.cache_clear()
    attack_stix._tactic_by_short_name.cache_clear()
    clear_cache()


def _ids_at_full_score(m: ProviderMapping, signal_id: str) -> frozenset[str]:
    return frozenset(
        e.technique_id for e in m.techniques_for_signal(signal_id, score=100)
    )


def test_abuseipdb_yaml_reproduces_legacy_dict() -> None:
    m = load_provider_mapping("abuseipdb")
    for cat, expected in _ABUSEIPDB_LEGACY.items():
        got = _ids_at_full_score(m, f"cat_{cat}")
        assert got == expected, f"cat_{cat}: got {got}, want {expected}"
    # No extra signals — full set match.
    assert m.signal_ids() == {f"cat_{c}" for c in _ABUSEIPDB_LEGACY}


def test_abuseipdb_high_score_gate() -> None:
    m = load_provider_mapping("abuseipdb")
    # Below threshold: T1566 dropped, T1496 still fires.
    below = {e.technique_id for e in m.techniques_for_signal("cat_11", score=50)}
    assert below == {"T1496"}
    # At threshold and above: both fire.
    at = {e.technique_id for e in m.techniques_for_signal("cat_11", score=80)}
    assert at == {"T1496", "T1566"}
    above = {e.technique_id for e in m.techniques_for_signal("cat_11", score=99)}
    assert above == {"T1496", "T1566"}
    # Score=None: gated emission filtered (matches legacy: no score → no T1566).
    none = {e.technique_id for e in m.techniques_for_signal("cat_11", score=None)}
    assert none == {"T1496"}


def test_greynoise_yaml_reproduces_legacy_dict() -> None:
    m = load_provider_mapping("greynoise")
    for tag, expected in _GREYNOISE_LEGACY.items():
        got = _ids_at_full_score(m, tag)
        assert got == expected, f"{tag}: got {got}, want {expected}"
    assert m.signal_ids() == set(_GREYNOISE_LEGACY)


def test_threatfox_yaml_reproduces_legacy_dict() -> None:
    m = load_provider_mapping("threatfox")
    for tt, expected in _THREATFOX_LEGACY.items():
        got = _ids_at_full_score(m, tt)
        assert got == expected, f"{tt}: got {got}, want {expected}"
    assert m.signal_ids() == set(_THREATFOX_LEGACY)


def test_feodo_yaml_emits_t1071_and_t1588() -> None:
    m = load_provider_mapping("feodo")
    got = _ids_at_full_score(m, "feodo_listed")
    assert got == {"T1071", "T1588"}


@pytest.mark.parametrize(
    "provider", ["abuseipdb", "greynoise", "feodo", "threatfox"]
)
def test_every_signal_has_external_reference(provider: str) -> None:
    m = load_provider_mapping(provider)
    for sig in m.signals:
        assert sig.external_reference.source_name
        assert sig.external_reference.url.startswith("http")


@pytest.mark.parametrize(
    "provider", ["abuseipdb", "greynoise", "feodo", "threatfox"]
)
def test_every_emission_has_mitre_url(provider: str) -> None:
    m = load_provider_mapping(provider)
    for sig in m.signals:
        for emission in sig.emissions:
            assert emission.mitre_url is not None, (
                f"{provider}/{sig.id}/{emission.technique_id} missing mitre_url"
            )
            assert emission.mitre_url.startswith(
                "https://attack.mitre.org/techniques/"
            )


def test_load_unknown_provider_raises() -> None:
    with pytest.raises(FileNotFoundError):
        load_provider_mapping("does_not_exist")


def test_unknown_technique_id_in_yaml_fails_closed(tmp_path: Path) -> None:
    bogus = tmp_path / "intel" / "bogus.yaml"
    bogus.parent.mkdir(parents=True)
    bogus.write_text(
        yaml.safe_dump(
            {
                "provider": "bogus",
                "mapping_version": "1",
                "attack_release": ">=15.1",
                "signals": [
                    {
                        "id": "sig_1",
                        "label": "Test",
                        "external_reference": {
                            "source_name": "test",
                            "url": "https://example.com",
                        },
                        "techniques": [{"technique_id": "T9999"}],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    # Point the loader at the temp file. We do this by patching the
    # loader's internal _data_path to resolve to the temp dir for the
    # 'bogus' provider only.
    from decnet.ttp.data import intel_loader

    original = intel_loader._data_path

    def fake_path(provider: str) -> Path:
        return bogus if provider == "bogus" else original(provider)

    intel_loader._data_path = fake_path  # type: ignore[assignment]
    intel_loader.clear_cache()
    try:
        with pytest.raises(attack_stix.AttackBundleError) as exc:
            load_provider_mapping("bogus")
        assert "T9999" in str(exc.value)
    finally:
        intel_loader._data_path = original  # type: ignore[assignment]
        intel_loader.clear_cache()


def test_yaml_provider_field_must_match_filename(tmp_path: Path) -> None:
    """A YAML claiming provider=X loaded from <Y>.yaml is rejected — drift catcher."""
    mismatched = tmp_path / "intel" / "abuseipdb.yaml"
    mismatched.parent.mkdir(parents=True)
    mismatched.write_text(
        yaml.safe_dump(
            {
                "provider": "wrong_name",
                "mapping_version": "1",
                "attack_release": ">=15.1",
                "signals": [],
            }
        ),
        encoding="utf-8",
    )
    from decnet.ttp.data import intel_loader

    original = intel_loader._data_path
    intel_loader._data_path = lambda _p: mismatched  # type: ignore[assignment]
    intel_loader.clear_cache()
    try:
        with pytest.raises(ValueError, match="does not match"):
            load_provider_mapping("abuseipdb")
    finally:
        intel_loader._data_path = original  # type: ignore[assignment]
        intel_loader.clear_cache()


def test_yaml_files_match_directory_listing() -> None:
    """Catch a YAML that's been added without a corresponding mapping
    or removed without cleanup. Keeps the data dir in sync with the
    test parametrize lists."""
    files = sorted(p.stem for p in _DATA_DIR.glob("*.yaml"))
    assert files == ["abuseipdb", "feodo", "greynoise", "threatfox"]
