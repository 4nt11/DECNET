# SPDX-License-Identifier: AGPL-3.0-or-later
"""Idempotency and replay-safety tests for ``compute_tag_uuid`` (E.2.2).

The deterministic UUIDv5 derivation is the load-bearing primitive
behind ``INSERT OR IGNORE`` replay safety: the worker must be able to
re-process the same source events any number of times — crash recovery,
backfill, manual re-run — and converge to the same tag set.

The replay-safety lock asserts the *exact* parameter set so a future
contributor adding ``created_at``, ``os.getpid()``, ``random.random()``
or any other non-deterministic input cannot silently break replay
safety; the test breaks first.
"""
from __future__ import annotations

import inspect
from typing import Optional

from hypothesis import given, settings
from hypothesis import strategies as st

from decnet.web.db.models.ttp import _TTP_TAG_NS, compute_tag_uuid


# ── Determinism ─────────────────────────────────────────────────────


_input_tuple = st.tuples(
    st.text(min_size=1, max_size=32),
    st.text(min_size=1, max_size=64),
    st.text(min_size=1, max_size=32),
    st.integers(min_value=0, max_value=10_000),
    st.text(min_size=1, max_size=16),
    st.one_of(st.none(), st.text(min_size=1, max_size=16)),
)


@given(t=_input_tuple)
@settings(max_examples=100, deadline=None)
def test_compute_tag_uuid_is_deterministic(
    t: tuple[str, str, str, int, str, Optional[str]],
) -> None:
    a = compute_tag_uuid(*t)
    b = compute_tag_uuid(*t)
    assert a == b


# ── Collision resistance ────────────────────────────────────────────


@given(
    tuples=st.lists(_input_tuple, min_size=2, max_size=200, unique=True),
)
@settings(max_examples=50, deadline=None)
def test_distinct_inputs_yield_distinct_uuids(
    tuples: list[tuple[str, str, str, int, str, Optional[str]]],
) -> None:
    uuids = {compute_tag_uuid(*t) for t in tuples}
    # Distinct input tuples → distinct UUIDs in the practical input
    # space. UUIDv5 is 122-bit; collisions in N≤200 are
    # vanishingly unlikely.
    assert len(uuids) == len(tuples)


# ── Golden-value lock ───────────────────────────────────────────────


def test_compute_tag_uuid_golden_value() -> None:
    """Pinned input → pinned UUID. Drift = breaking change.

    Worked example from the design doc (``find_recursive_root`` / R0014
    on ``cmd_42``). If this assertion ever needs to flip, every
    existing tag UUID in production has been silently invalidated —
    treat as a migration event.
    """
    assert (
        compute_tag_uuid("command", "cmd_42", "R0014", 2, "T1083", None)
        == "9aa491e5-f03b-5d8f-9eb5-161becedcdd6"
    )
    assert (
        compute_tag_uuid("command", "cmd_42", "R0015", 1, "T1548", "T1548.001")
        == "4fd57b14-c135-544c-97d9-4fabc1051584"
    )


def test_namespace_constant_is_pinned() -> None:
    """The namespace UUID itself is part of the contract — regenerating
    it would invalidate every tag UUID."""
    assert str(_TTP_TAG_NS) == "1ca31f08-5522-5aae-8371-fe81f0e39de3"


# ── Replay-safety lock: parameter set ───────────────────────────────


def test_compute_tag_uuid_parameter_set_is_locked() -> None:
    """The accepted inputs MUST be exactly the six identity fields.

    Adding ``created_at``, a process PID, a random salt, or any other
    non-deterministic input silently breaks replay safety. This test
    is the trip-wire: a contributor must update it deliberately to
    change the input set.
    """
    sig = inspect.signature(compute_tag_uuid)
    names = tuple(sig.parameters)
    assert names == (
        "source_kind",
        "source_id",
        "rule_id",
        "rule_version",
        "technique_id",
        "sub_technique_id",
    )
