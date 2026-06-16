# SPDX-License-Identifier: AGPL-3.0-or-later
"""IPv6 link-local leak lifter — opsec-failure tagger (R0059).

Reads ``ipv6_leak`` source-kind events emitted by the passive sniffer
(SnifferEngine._on_ipv6_packet) and the active prober (_ipv6_leak_phase)
and emits a Command-and-Control / Proxy technique tag (T1090) when a
fe80:: address is observed for an attacker known to be behind an IPv4 VPN.

Evidence is pinned to :class:`~decnet.web.db.models.ttp.Ipv6LinkLocalLeakEvidence`.
The ``iid_kind`` field carries classification confidence context so analysts
can filter EUI-64 (strongest, MAC-derived) from stable-privacy or temporary IIDs.
"""
from __future__ import annotations

from typing import Any, Final

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.ttp.impl._emit import emit_tags
from decnet.ttp.impl._rule_index import RuleIndex
from decnet.ttp.impl._state import is_active
from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleStore
from decnet.web.db.models.ttp import TTPTag

_OWNED_PREFIX: Final[str] = "lifter:ipv6_link_local_leak"


def _p_ipv6_leak(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    addr: str = payload.get("addr", "") or payload.get("src_ip", "")
    if not addr.lower().startswith("fe80:"):
        return None
    return {
        "addr": addr,
        "mac_oui": payload.get("mac_oui", ""),
        "iid_kind": payload.get("iid_kind", "unknown"),
        "vector": payload.get("vector", ""),
        "on_iface": payload.get("on_iface", ""),
        "attacker_v4": payload.get("attacker_v4", "") or payload.get("attacker_ip", ""),
        "observed_at": payload.get("observed_at", ""),
    }


class Ipv6LeakLifter(TolerantTagger):
    name = "ipv6_leak"
    HANDLES = frozenset({"ipv6_leak"})

    def __init__(self, store: RuleStore) -> None:
        self._store = store
        self._index = RuleIndex()

    @classmethod
    def _owns(cls, rule: CompiledRule) -> bool:
        kind = rule.match_spec.get("kind", "")
        return isinstance(kind, str) and kind == _OWNED_PREFIX

    async def watch_store(self) -> None:
        await self._index.watch(self._store, predicate=self._owns)

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        out: list[TTPTag] = []
        for rule in self._index.values():
            if event.source_kind not in rule.applies_to:
                continue
            if not is_active(rule.state):
                continue
            evidence = _p_ipv6_leak(rule.match_spec, event.payload)
            if evidence is None:
                continue
            out.extend(emit_tags(rule, event, evidence))
        return out


__all__ = ["Ipv6LeakLifter"]
