"""Boot-time ATT&CK bundle validation for lifters and the UKC tactic map.

Mirrors what :func:`decnet.ttp.worker.run_ttp_worker_loop` runs at
startup so a CI run catches the same drift the worker would refuse to
boot on. The two validators (``intel_lifter.validate_against_attack_bundle``
and ``ukc.validate_against_attack_bundle``) are the entry points; this
module also asserts the negative path (a typoed ID inside the
collection function raises :class:`AttackBundleError`) so a future
refactor that loses the assertion fails loudly here rather than in
production.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from decnet.clustering import ukc
from decnet.ttp import attack_stix
from decnet.ttp.impl import intel_lifter

_REPO_BUNDLE = Path(__file__).resolve().parents[2] / "enterprise-attack-19.0.json"


@pytest.fixture(autouse=True)
def _pin_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECNET_ATTACK_BUNDLE", str(_REPO_BUNDLE))
    attack_stix._data = None
    attack_stix._loaded_path = None
    attack_stix._attack_pattern_by_id.cache_clear()
    attack_stix._tactic_by_id.cache_clear()
    attack_stix._tactic_by_short_name.cache_clear()


def test_intel_lifter_emissions_resolve_in_bundle() -> None:
    intel_lifter.validate_against_attack_bundle()


def test_intel_lifter_emission_set_is_complete() -> None:
    ids = intel_lifter.all_emitted_technique_ids()
    # Decision-flow constants should be present even though they don't
    # appear in the lookup tables (see _greynoise_decisions /
    # _feodo_decisions).
    assert {"T1071", "T1595", "T1588"}.issubset(ids)
    # Spot-check at least one entry from each table.
    assert "T1110" in ids  # AbuseIPDB cat 5/22
    assert "T1090" in ids  # GreyNoise tor_exit_node
    assert "T1056" in ids  # ThreatFox cc_skimming


def test_ukc_tactic_map_resolves_in_bundle() -> None:
    ukc.validate_against_attack_bundle()


def test_ukc_ics_tactics_are_exempt_from_validation() -> None:
    # ICS tactics aren't in the enterprise bundle, but the validator
    # tolerates them via the _NON_ENTERPRISE_TACTICS exempt set.
    assert "TA0100" in ukc._NON_ENTERPRISE_TACTICS
    assert not attack_stix.tactic_exists("TA0100")
    # And the validator passes (tested above) despite TA0100..TA0106
    # being in ATTACK_TACTIC_TO_UKC.


def test_validator_raises_when_unknown_id_injected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Inject a bogus tactic into the map for the duration of the test.
    bogus = "TA9999"
    monkeypatch.setitem(ukc.ATTACK_TACTIC_TO_UKC, bogus, ukc.UKCPhase.IMPACT)
    with pytest.raises(attack_stix.AttackBundleError) as exc:
        ukc.validate_against_attack_bundle()
    assert bogus in str(exc.value)


def test_credential_lifter_t1078_resolves() -> None:
    # credential_lifter has a single hardcoded T1078 reference; cover
    # it explicitly so a future ATT&CK release that retires T1078
    # surfaces here as well as in the rule-pack coverage test.
    assert attack_stix.technique_exists("T1078")
