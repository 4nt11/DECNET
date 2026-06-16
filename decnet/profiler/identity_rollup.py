# SPDX-License-Identifier: AGPL-3.0-or-later
"""Identity-level fingerprint rollup.

The clusterer mints :class:`AttackerIdentity` rows (and merges them) from
union-find over per-IP :class:`Attacker` observations. Each ``Attacker``
row already carries a ``fingerprints`` JSON list — the output of the
profiler's ``_build_record`` flatten of every ``bounty_type='fingerprint'``
bounty seen for that IP. This module distils that per-observation list
into the cross-observation summary columns on ``AttackerIdentity``:

* ``ja3_hashes``        — TLS ClientHello fingerprints
* ``hassh_hashes``      — SSH KEX fingerprints
* ``tls_cert_sha256``   — leaf cert SHA-256s presented by attacker-run
                          TLS servers (active-prober capture)

These are JSON-serialised ``list[str]`` columns shaped for federation
gossip — same wire format the campaign clusterer reads. The values are
deduplicated and sorted so two clusterer runs over the same input produce
byte-identical column writes.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Optional


# Bounty payload key per fingerprint family. Only fingerprints whose
# payload carries a stable scalar identifier roll up cleanly here —
# tcpfp / http_quirks / ja4l etc. don't fit the "list of hashes" shape
# and stay out of the rollup until they get their own columns.
_PAYLOAD_KEY_BY_FP_TYPE: dict[str, str] = {
    "ja3":             "ja3",
    "hassh_server":    "hash",
    "tls_certificate": "cert_sha256",
    "ja4h":            "ja4h",
    "ja4_quic":        "ja4_quic",
}

_COLUMN_BY_FP_TYPE: dict[str, str] = {
    "ja3":             "ja3_hashes",
    "hassh_server":    "hassh_hashes",
    "tls_certificate": "tls_cert_sha256",
    "ja4h":            "ja4h_hashes",
    "ja4_quic":        "ja4_quic_hashes",
}


def _payload_of(entry: Any) -> dict[str, Any]:
    """Return the payload dict from a fingerprint bounty entry."""
    if not isinstance(entry, dict):
        return {}
    p = entry.get("payload")
    if isinstance(p, dict):
        return p
    if isinstance(p, str):
        try:
            parsed = json.loads(p)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    # Some legacy callers may have flattened the payload onto the entry.
    return entry


def _parse_fingerprints(raw: Any) -> list[dict[str, Any]]:
    """Best-effort parse of an Attacker.fingerprints column value."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [e for e in raw if isinstance(e, dict)]
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError):
            return []
        return [e for e in decoded if isinstance(e, dict)] if isinstance(decoded, list) else []
    return []


def extract_fp_summaries(
    member_rows: Iterable[dict[str, Any]],
) -> dict[str, Optional[str]]:
    """Aggregate fingerprint hashes across the given Attacker rows.

    Returns a dict with keys ``ja3_hashes``, ``hassh_hashes``,
    ``tls_cert_sha256`` — each value is either a JSON-encoded
    ``list[str]`` (deduped, sorted) or ``None`` when no signal is
    present. ``None`` is preferred over ``"[]"`` so the column stays
    NULL and downstream readers can distinguish "no data yet" from
    "actively known to be empty".

    Pure: no DB, no clock, no I/O. The clusterer drives the call.
    """
    buckets: dict[str, set[str]] = {col: set() for col in _COLUMN_BY_FP_TYPE.values()}

    for row in member_rows:
        for entry in _parse_fingerprints(row.get("fingerprints")):
            payload = _payload_of(entry)
            fp_type = payload.get("fingerprint_type")
            if not isinstance(fp_type, str):
                continue
            payload_key = _PAYLOAD_KEY_BY_FP_TYPE.get(fp_type)
            column = _COLUMN_BY_FP_TYPE.get(fp_type)
            if payload_key is None or column is None:
                continue
            value = payload.get(payload_key)
            if isinstance(value, str) and value:
                buckets[column].add(value)

    return {
        column: (json.dumps(sorted(values)) if values else None)
        for column, values in buckets.items()
    }
