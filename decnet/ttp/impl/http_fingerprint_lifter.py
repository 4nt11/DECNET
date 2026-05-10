"""HTTP fingerprint lifter — JA4H / H2-settings / H3-settings / JA4-QUIC tagger.

Reads ``http_fingerprint`` source-kind events and emits Reconnaissance
techniques when fingerprint patterns match known scanner or attacker-tooling
profiles.

Covered techniques:
* T1592.002 — Gather Victim Host Information: Software (scanner-JA4H match)
* T1046    — Network Service Discovery (h2/h3 protocol probing)
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.ttp.impl._emit import emit_tags
from decnet.ttp.impl._rule_index import RuleIndex
from decnet.ttp.impl._state import is_active
from decnet.ttp.store.base import RuleStore
from decnet.web.db.models.ttp import TTPTag


Predicate = Callable[
    [dict[str, Any], dict[str, Any]],
    "dict[str, Any] | None",
]

# Known scanner JA4H prefixes. The method+version+cookie+referer component
# (first segment before the first underscore) is stable across tool versions
# while the header hash varies with User-Agent spoofing. Matching on the
# prefix catches deliberate UA spoofing that forgets to shuffle header order.
_SCANNER_JA4H_PREFIXES: Final[frozenset[str]] = frozenset({
    "GE11nn0000",  # curl default (no cookie, no referer, no lang)
    "GE20nn0000",  # curl --http2
    "GE30nn0000",  # curl --http3
    "GE11nn0000",  # wget
    "GE11nn0000",  # python-requests (no lang header)
})

# h2/h3 probing without a browser User-Agent is a service-discovery tell.
_H2_PROBE_PROTOCOLS: Final[frozenset[str]] = frozenset({"h2", "h2c", "h3"})


def _p_scanner_ja4h(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    ja4h: str = payload.get("ja4h", "")
    if not ja4h:
        return None
    prefix = ja4h.split("_")[0] if "_" in ja4h else ja4h[:10]
    catalogues_raw = spec.get("catalogues", list(_SCANNER_JA4H_PREFIXES))
    catalogues = set(catalogues_raw) if isinstance(catalogues_raw, list) else _SCANNER_JA4H_PREFIXES
    if prefix not in catalogues:
        return None
    return {
        "kind": "ja4h",
        "hash": ja4h,
        "protocol": payload.get("protocol", "h1"),
        "client_ip": payload.get("client_ip", ""),
        "seen_at": payload.get("seen_at", ""),
        "raw": None,
    }


def _p_h2_h3_probe(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    fp_type: str = payload.get("fingerprint_type", "")
    if fp_type not in ("http2_settings", "http3_settings"):
        return None
    protocol = "h2" if fp_type == "http2_settings" else "h3"
    return {
        "kind": fp_type,
        "hash": "",
        "protocol": protocol,
        "client_ip": payload.get("client_ip", ""),
        "seen_at": payload.get("seen_at", ""),
        "raw": payload.get("settings"),
    }


def _p_quic_probe(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    ja4q: str = payload.get("ja4_quic", "")
    if not ja4q:
        return None
    return {
        "kind": "ja4_quic",
        "hash": ja4q,
        "protocol": "h3",
        "client_ip": payload.get("client_ip", ""),
        "seen_at": payload.get("seen_at", ""),
        "raw": None,
    }


_PREDICATES: Final[dict[str, Predicate]] = {
    "HFP-0001": _p_scanner_ja4h,
    "HFP-0002": _p_h2_h3_probe,
    "HFP-0003": _p_quic_probe,
}


class HttpFingerprintLifter(TolerantTagger):
    """Tags HTTP-layer fingerprint events with MITRE ATT&CK techniques."""

    HANDLES: frozenset[str] = frozenset({"http_fingerprint"})

    def __init__(self, store: RuleStore) -> None:
        self._index = RuleIndex()

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        payload = event.payload if isinstance(event.payload, dict) else {}
        tags: list[TTPTag] = []
        for rule_id, predicate in _PREDICATES.items():
            rule = self._index.get(rule_id)
            if rule is None or not is_active(rule.state):
                continue
            evidence = predicate(rule.match_spec, payload)
            if evidence is None:
                continue
            tags.extend(emit_tags(rule, event, evidence))
        return tags
