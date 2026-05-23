# SPDX-License-Identifier: AGPL-3.0-or-later
"""E.3.15 — production phase-handoff edge fires from ttp_tag rows.

The UKC bridge (``tactic_to_ukc_phase`` + ``OBSERVABLE_PHASES``) was
already unit-tested in :mod:`tests.clustering.test_ukc_bridge`. The
load-bearing payoff lands here: the production-row adapter
:func:`from_identity_row` now consumes per-identity tag observations
and populates the phase-handoff maps so
:func:`combined_campaign_weight` lights up on real DB rows — not just
the synthetic-fixture path.
"""
from __future__ import annotations

from typing import Any

from decnet.clustering.campaign.impl.connected_components import (
    from_identity_row,
)
from decnet.clustering.campaign.impl.similarity import (
    CAMPAIGN_EDGE_THRESHOLD,
    combined_campaign_weight,
    phase_handoff_weight,
)
from decnet.clustering.ukc import UKCPhase


# A → C2 (handoff-out) on decky D at t=100; B → DISCOVERY (handoff-in)
# on the same decky at t=200. Within the 24h window → edge weight 1.0.
def _row(uuid: str) -> dict[str, Any]:
    return {
        "uuid": uuid,
        "ja3_hashes": None,
        "hassh_hashes": None,
        "payload_simhashes": None,
        "c2_endpoints": None,
    }


def _phases(decky: str, tactic: str, ts: float) -> dict[str, Any]:
    return {"decky_id": decky, "tactic": tactic, "created_at_ts": ts}


def test_from_identity_row_populates_phase_maps_from_tags() -> None:
    feat = from_identity_row(
        _row("id-A"),
        ttp_decky_phases=[
            _phases("d1", "TA0007", 100.0),  # DISCOVERY
            _phases("d1", "TA0011", 200.0),  # COMMAND_AND_CONTROL
        ],
    )
    assert feat.first_phase_per_decky == {"d1": UKCPhase.DISCOVERY.value}
    assert feat.last_phase_per_decky == {"d1": UKCPhase.COMMAND_AND_CONTROL.value}
    assert feat.first_seen_per_decky == {"d1": 100.0}
    assert feat.last_seen_per_decky == {"d1": 200.0}
    assert "d1" in feat.decky_set


def test_from_identity_row_skips_unmappable_tactic() -> None:
    feat = from_identity_row(
        _row("id-X"),
        ttp_decky_phases=[
            _phases("d1", "TA9999", 100.0),  # unknown tactic
        ],
    )
    assert feat.first_phase_per_decky == {}
    assert feat.last_phase_per_decky == {}


def test_phase_handoff_fires_on_production_rows() -> None:
    """Two identities sharing a decky with C2 → DISCOVERY in window."""
    a = from_identity_row(
        _row("id-A"),
        ttp_decky_phases=[
            _phases("d1", "TA0011", 100.0),  # last on A: C2 (handoff-out)
        ],
    )
    b = from_identity_row(
        _row("id-B"),
        ttp_decky_phases=[
            _phases("d1", "TA0007", 200.0),  # first on B: DISCOVERY (handoff-in)
        ],
    )
    assert phase_handoff_weight(a, b) == 1.0
    # The combined weight bundles phase-handoff with shared-decky and
    # other signals — pin that the production-row pair clears the
    # campaign-edge threshold (the moment the doc says we know this
    # whole project paid off).
    assert combined_campaign_weight(a, b) >= CAMPAIGN_EDGE_THRESHOLD


def test_phase_handoff_zero_when_no_decky_overlap() -> None:
    a = from_identity_row(
        _row("id-A"),
        ttp_decky_phases=[_phases("d1", "TA0011", 100.0)],
    )
    b = from_identity_row(
        _row("id-B"),
        ttp_decky_phases=[_phases("d2", "TA0007", 200.0)],
    )
    assert phase_handoff_weight(a, b) == 0.0


def test_from_identity_row_empty_tags_keeps_legacy_behavior() -> None:
    """No ttp_decky_phases → phase maps stay empty (the pre-E.3.15
    production behaviour). Tests that depend on the empty path keep
    passing without modification.
    """
    feat = from_identity_row(_row("id-A"))
    assert feat.first_phase_per_decky == {}
    assert feat.last_phase_per_decky == {}
    assert feat.decky_set == frozenset()
