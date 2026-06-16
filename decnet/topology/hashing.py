# SPDX-License-Identifier: AGPL-3.0-or-later
"""Canonical hash of a hydrated topology dict.

Both master and agent need to agree on "is the applied state the one
the master intends?".  We answer that by hashing the hydrated topology
blob on both sides and comparing the hex digests.  The function has to
be **pure** and **deterministic**: same logical state → same hash, no
matter the dict-key order, no matter the timezone of a ``created_at``.

Normalisation rules (applied to a deep copy — input is never mutated):

- Drop fields that change on every read but don't change behaviour:
  ``created_at``, ``status_changed_at``, ``updated_at``, ``last_seen``,
  ``status``, ``version``, ``last_error``.
- Drop purely-cosmetic canvas positions (``x``, ``y``, ``w``, ``h``)
  everywhere — they're client-side layout, not deployment state.
- Leave everything else alone; sort-keys=True + ``separators``
  collapse whitespace and fix ordering.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

# Fields that vary over time or come from layout and must NOT feed the
# applied-state hash.  Dropped at every nesting level.
_VOLATILE_KEYS = frozenset(
    {
        "created_at",
        "status_changed_at",
        "updated_at",
        "last_seen",
        "status",
        "version",
        "last_error",
        "x",
        "y",
        "w",
        "h",
    }
)


def _strip(value: Any) -> Any:
    """Return a deep copy of *value* with volatile keys removed."""
    if isinstance(value, dict):
        return {k: _strip(v) for k, v in value.items() if k not in _VOLATILE_KEYS}
    if isinstance(value, list):
        return [_strip(v) for v in value]
    return value


def canonical_hash(hydrated: dict) -> str:
    """Return the SHA-256 hex digest of *hydrated*'s canonical form."""
    normalised = _strip(hydrated)
    blob = json.dumps(
        normalised,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


__all__ = ["canonical_hash"]
