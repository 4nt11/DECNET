"""OS / TCP fingerprint rollup for DECNET attacker profiles.

Consumes sniffer-emitted `tcp_syn_fingerprint` / `tcp_flow_timing` events and
active prober `tcpfp_fingerprint` events; derives a per-attacker summary
(os_guess, hop_distance, tcp_fingerprint snapshot, retransmit_count).
"""

from __future__ import annotations

import statistics
from collections import Counter
from typing import Any

from decnet.correlation.parser import LogEvent
from decnet.telemetry import traced as _traced

# Sniffer-emitted packet events that feed into fingerprint rollup.
_SNIFFER_SYN_EVENT: str  = "tcp_syn_fingerprint"
_SNIFFER_FLOW_EVENT: str = "tcp_flow_timing"
# Prober-emitted active-probe result (SYN-ACK fingerprint of attacker machine).
_PROBER_TCPFP_EVENT: str = "tcpfp_fingerprint"
# Prober-emitted HASSHServer fingerprint; carries the raw kex_algorithms string.
_PROBER_HASSH_EVENT: str = "hassh_fingerprint"
# Sniffer-emitted SSH client identification string (RFC 4253 §4.2).
_SNIFFER_SSH_BANNER_EVENT: str = "ssh_client_banner"

# Canonical initial TTL for each coarse OS bucket.  Used to derive hop
# distance when only the observed TTL is available (prober path).
_INITIAL_TTL: dict[str, int] = {
    "linux":    64,
    "windows":  128,
    "embedded": 255,
}


def _os_from_ttl(ttl_str: str | None) -> str | None:
    """Derive a coarse OS guess from observed TTL when p0f has no match."""
    if not ttl_str:
        return None
    try:
        ttl = int(ttl_str)
    except (TypeError, ValueError):
        return None
    if 55 <= ttl <= 70:
        return "linux"
    if 115 <= ttl <= 135:
        return "windows"
    if 235 <= ttl <= 255:
        return "embedded"
    return None


def _int_or_none(v: Any) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@_traced("profiler.sniffer_rollup")
def sniffer_rollup(events: list[LogEvent]) -> dict[str, Any]:
    """
    Roll up sniffer-emitted `tcp_syn_fingerprint` and `tcp_flow_timing`
    events into a per-attacker summary.

    OS guess priority:
      1. Modal p0f label from os_guess field (if not "unknown"/empty).
      2. TTL-based coarse bucket (linux / windows / embedded) as fallback.
    Hop distance: median of non-zero reported values only.
    """
    os_guesses: list[str] = []
    ttl_values: list[str] = []
    hops: list[int] = []
    tcp_fp: dict[str, Any] | None = None
    retransmits = 0
    kex_order_raw: list[str] = []
    _kex_seen: set[str] = set()
    ssh_client_banners: list[str] = []
    _ssh_banner_seen: set[str] = set()

    for e in events:
        if e.event_type == _SNIFFER_SYN_EVENT:
            og = e.fields.get("os_guess")
            if og and og != "unknown":
                os_guesses.append(og)

            # Collect raw TTL for fallback OS derivation.
            ttl_raw = e.fields.get("ttl") or e.fields.get("initial_ttl")
            if ttl_raw:
                ttl_values.append(ttl_raw)

            # Only include hop distances that are valid and non-zero.
            hop_raw = e.fields.get("hop_distance")
            if hop_raw:
                try:
                    hop_val = int(hop_raw)
                    if hop_val > 0:
                        hops.append(hop_val)
                except (TypeError, ValueError):
                    pass

            # Keep the latest fingerprint snapshot.
            tcp_fp = {
                "window": _int_or_none(e.fields.get("window")),
                "wscale": _int_or_none(e.fields.get("wscale")),
                "mss": _int_or_none(e.fields.get("mss")),
                "options_sig": e.fields.get("options_sig", ""),
                "has_sack": e.fields.get("has_sack") == "true",
                "has_timestamps": e.fields.get("has_timestamps") == "true",
            }

        elif e.event_type == _SNIFFER_FLOW_EVENT:
            try:
                retransmits += int(e.fields.get("retransmits", "0"))
            except (TypeError, ValueError):
                pass

        elif e.event_type == _PROBER_HASSH_EVENT:
            # Prober HASSHServer probe: preserve the raw kex_algorithms list
            # for post-hoc ordering analysis. Dedup because a single attacker
            # SSH service will emit the same list per port/probe cycle.
            kex = e.fields.get("kex_algorithms")
            if kex and kex not in _kex_seen:
                kex_order_raw.append(kex)
                _kex_seen.add(kex)

        elif e.event_type == _SNIFFER_SSH_BANNER_EVENT:
            # Sniffer-observed SSH identification string from attacker.
            # Dedup: the same attacker will reuse the same client banner
            # across flows/reconnects; record distinct values in order seen.
            banner = e.fields.get("ssh_version")
            if banner and banner not in _ssh_banner_seen:
                ssh_client_banners.append(banner)
                _ssh_banner_seen.add(banner)

        elif e.event_type == _PROBER_TCPFP_EVENT:
            # Active-probe result: prober sent SYN to attacker, got SYN-ACK back.
            # Field names differ from the passive sniffer (different emitter).
            ttl_raw = e.fields.get("ttl")
            if ttl_raw:
                ttl_values.append(ttl_raw)

                # Derive hop distance from observed TTL vs canonical initial TTL.
                os_hint = _os_from_ttl(ttl_raw)
                if os_hint:
                    initial = _INITIAL_TTL.get(os_hint)
                    if initial:
                        try:
                            hop_val = initial - int(ttl_raw)
                            if hop_val > 0:
                                hops.append(hop_val)
                        except (TypeError, ValueError):
                            pass

            # Prober uses window_size/window_scale/options_order instead of
            # the sniffer's window/wscale/options_sig.
            tcp_fp = {
                "window":         _int_or_none(e.fields.get("window_size")),
                "wscale":         _int_or_none(e.fields.get("window_scale")),
                "mss":            _int_or_none(e.fields.get("mss")),
                "options_sig":    e.fields.get("options_order", ""),
                "has_sack":       e.fields.get("sack_ok") == "1",
                "has_timestamps": e.fields.get("timestamp") == "1",
            }

    # Mode for the OS bucket — most frequently observed label.
    os_guess: str | None = None
    if os_guesses:
        os_guess = Counter(os_guesses).most_common(1)[0][0]
    else:
        # TTL-based fallback: use the most common observed TTL value.
        if ttl_values:
            modal_ttl = Counter(ttl_values).most_common(1)[0][0]
            os_guess = _os_from_ttl(modal_ttl)

    # Median hop distance (robust to the occasional weird TTL).
    hop_distance: int | None = None
    if hops:
        hop_distance = int(statistics.median(hops))

    return {
        "os_guess": os_guess,
        "hop_distance": hop_distance,
        "tcp_fingerprint": tcp_fp or {},
        "retransmit_count": retransmits,
        "kex_order_raw": kex_order_raw,
        "ssh_client_banners": ssh_client_banners,
    }
