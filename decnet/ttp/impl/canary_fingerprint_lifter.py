# SPDX-License-Identifier: AGPL-3.0-or-later
"""Canary fingerprint lifter — browser-payload derived technique tagger (E.3.11).

Reads canary-payload fingerprints (navigator properties, canvas hashes,
proxy/VPN leakage signatures) per Appendix A.9 and emits Discovery /
Defense-Evasion techniques. Evidence shape is pinned to
:class:`~decnet.web.db.models.ttp.CanaryFingerprintEvidence`
(``metric`` + ``matched_signature``) — raw fingerprint blobs never
land in the tag payload. The composite identity hash matching across
IPs is explicitly NOT a TTP (TTP_TAGGING.md §"Identity-merge guard
rail"); the lifter does not emit on it.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.ttp.impl._emit import emit_tags
from decnet.ttp.impl._rule_index import RuleIndex
from decnet.ttp.impl._state import is_active
from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleStore
from decnet.web.db.models.ttp import TTPTag


Predicate = Callable[
    [dict[str, Any], dict[str, Any]],
    "dict[str, Any] | None",
]


def _p_webdriver(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    if payload.get("navigator_webdriver") is True:
        return {
            "metric": "navigator_webdriver",
            "matched_signature": "navigator.webdriver_true",
        }
    return None


def _p_automation_hash(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    catalogues_raw = spec.get("catalogues", [])
    catalogues = (
        {c for c in catalogues_raw if isinstance(c, str)}
        if isinstance(catalogues_raw, list)
        else set()
    )
    matched = payload.get("canvas_audio_hash_match") or payload.get("matched_tool")
    if isinstance(matched, str) and (not catalogues or matched in catalogues):
        return {
            "metric": "canvas_audio_hash",
            "matched_signature": matched,
            "matched_tool": matched,
        }
    return None


def _p_webrtc_leak(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    if payload.get("webrtc_geo_mismatch") is True:
        return {
            "metric": "webrtc_geo_mismatch",
            "matched_signature": "webrtc_private_vs_source_ip",
        }
    return None


def _p_tz_lang_mismatch(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    tz_zones = payload.get("tz_mismatch_zones")
    lang_mismatch = payload.get("lang_country_mismatch") is True
    tz_hit = isinstance(tz_zones, int) and tz_zones >= 3
    if tz_hit:
        return {
            "metric": "timezone_geo_mismatch",
            "matched_signature": f"tz_zones>={tz_zones}",
        }
    if lang_mismatch:
        return {
            "metric": "language_country_mismatch",
            "matched_signature": "lang_vs_source_country",
        }
    return None


def _p_platform_inconsistency(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    if payload.get("platform_ua_inconsistent") is True:
        return {
            "metric": "platform_ua_mismatch",
            "matched_signature": "navigator.platform_vs_userAgent",
        }
    if payload.get("ua_webgl_mismatch") is True:
        return {
            "metric": "ua_webgl_mismatch",
            "matched_signature": "userAgent_vs_webgl_renderer",
        }
    return None


_PREDICATES: Final[dict[str, Predicate]] = {
    "lifter:canary_webdriver": _p_webdriver,
    "lifter:canary_automation_hash": _p_automation_hash,
    "lifter:canary_webrtc_leak": _p_webrtc_leak,
    "lifter:canary_tz_lang_mismatch": _p_tz_lang_mismatch,
    "lifter:canary_platform_inconsistency": _p_platform_inconsistency,
}


class CanaryFingerprintLifter(TolerantTagger):
    name = "canary_fingerprint"
    HANDLES = frozenset({"canary_fingerprint"})
    OWNED_PREFIX: Final[str] = "lifter:canary_"

    def __init__(self, store: RuleStore) -> None:
        self._store = store
        self._index = RuleIndex()

    @classmethod
    def _owns(cls, rule: CompiledRule) -> bool:
        kind = rule.match_spec.get("kind", "")
        return isinstance(kind, str) and kind.startswith(cls.OWNED_PREFIX)

    async def watch_store(self) -> None:
        await self._index.watch(self._store, predicate=self._owns)

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        out: list[TTPTag] = []
        for rule in self._index.values():
            if event.source_kind not in rule.applies_to:
                continue
            if not is_active(rule.state):
                continue
            kind = rule.match_spec.get("kind", "")
            handler = _PREDICATES.get(kind)
            if handler is None:
                continue
            extra = handler(rule.match_spec, event.payload)
            if extra is None:
                continue
            # Evidence shape is pinned by CanaryFingerprintEvidence —
            # only metric + matched_signature land in the tag. Raw
            # fingerprint blobs explicitly NOT carried.
            evidence: dict[str, Any] = {
                "metric": extra.get("metric", ""),
                "matched_signature": extra.get("matched_signature", ""),
            }
            out.extend(emit_tags(rule, event, evidence))
        return out


__all__ = ["CanaryFingerprintLifter"]
