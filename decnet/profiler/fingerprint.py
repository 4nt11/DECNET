"""OS / TCP fingerprint rollup for DECNET attacker profiles.

Consumes sniffer-emitted `tcp_syn_fingerprint` / `tcp_flow_timing` events and
active prober `tcpfp_fingerprint` events; derives a per-attacker summary
(os_guess, hop_distance, tcp_fingerprint snapshot, retransmit_count).
"""

from __future__ import annotations

import logging
import statistics
from collections import Counter
from typing import Any, Optional

from decnet.correlation.parser import LogEvent
from decnet.prober.osfp import OsMatch, get_all_providers
from decnet.sniffer.p0f import initial_ttl as _initial_ttl_bucket
from decnet.telemetry import traced as _traced

_log = logging.getLogger("decnet.profiler.fingerprint")

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


def _match_via_osfp_providers(
    tcp_fp: dict[str, Any] | None,
    modal_ttl: str | None,
    context: str,
) -> Optional[OsMatch]:
    """Feed the current tcp_fp snapshot through every enabled OS-fingerprint
    provider and return the best match, or None.

    Must never raise — factory / provider failures collapse to None so a
    corrupt .fp file or misconfigured DECNET_OSFP_PROVIDERS env var can't
    wedge the profile rebuild for an entire attacker. Worst case: the
    caller falls back to the modal-label / TTL-bucket path that existed
    before this wiring.
    """
    if not tcp_fp:
        return None
    # Convert the observed TTL (which may be N hops below the initial TTL
    # the remote OS uses) to the canonical initial-TTL bucket the p0f v2
    # DB expects (32 / 64 / 128 / 255).
    try:
        ttl_int = int(modal_ttl) if modal_ttl is not None else None
    except (TypeError, ValueError):
        ttl_int = None
    initial_ttl_bucket = _initial_ttl_bucket(ttl_int) if ttl_int is not None else None

    obs: dict[str, Any] = {
        "window":      tcp_fp.get("window"),
        "wscale":      tcp_fp.get("wscale"),
        "mss":         tcp_fp.get("mss"),
        "options_sig": tcp_fp.get("options_sig"),
        "ttl":         initial_ttl_bucket,
        # DF and total_len are not captured today — passed as None so
        # Signature.score treats them as soft fields (skip check when
        # missing). Promote to hard fields once the sniffer/prober
        # emit them on tcp_syn_fingerprint / tcpfp_fingerprint.
        "df":          None,
        "total_len":   None,
        # Sniffer doesn't yet emit a quirks SD field, so the matcher
        # sees an empty set — which matches signatures with no quirks
        # (the common case) but not signatures with specific quirks.
        # That's correct behaviour, not a bug.
        "quirks":      frozenset(),
        "context":     context,
    }

    best: Optional[OsMatch] = None
    try:
        providers = get_all_providers()
    except Exception as exc:  # noqa: BLE001 — must not propagate
        _log.warning("osfp: provider init failed, skipping match: %s", exc)
        return None
    for provider in providers:
        try:
            match = provider.match(obs)
        except Exception as exc:  # noqa: BLE001 — must not propagate
            _log.warning("osfp: provider %s raised during match: %s", provider.name, exc)
            continue
        if match is None:
            continue
        if best is None or match.confidence > best.confidence:
            best = match
    return best


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
    ipid_latest: str | None = None
    isn_latest: str | None = None
    # Tracks which event set tcp_fp last — picks the provider "context"
    # (syn vs synack) when we feed the p0f-v2 matcher below.
    tcp_fp_context: str = "syn"
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
                "tos": _int_or_none(e.fields.get("tos")),
                "dscp": _int_or_none(e.fields.get("dscp")),
                "ecn": _int_or_none(e.fields.get("ecn")),
            }
            # Sequence classifications converge as samples accumulate; the
            # most recent non-"unknown" label wins so a later "unknown" event
            # (e.g. a deque reset) doesn't overwrite a confident verdict.
            ipid_class = e.fields.get("ipid_class")
            if ipid_class and ipid_class != "unknown":
                ipid_latest = ipid_class
            tcp_fp["ipid_class"] = ipid_latest
            isn_class = e.fields.get("isn_class")
            if isn_class and isn_class != "unknown":
                isn_latest = isn_class
            tcp_fp["isn_class"] = isn_latest
            tcp_fp_context = "syn"

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
                "tos":            _int_or_none(e.fields.get("tos")),
                "dscp":           _int_or_none(e.fields.get("dscp")),
                "ecn":            _int_or_none(e.fields.get("ecn")),
            }
            tcp_fp_context = "synack"  # prober sent SYN, captured attacker's SYN-ACK

    # OS-guess resolution chain:
    #   1. p0f-v2 (or whichever providers DECNET_OSFP_PROVIDERS enables)
    #      matched against the latest tcp_fp snapshot — the 375-sig
    #      vendored DB is far more discriminating than what follows.
    #   2. Modal sniffer-emitted label from the old ~10-sig hand-rolled
    #      table in decnet/sniffer/p0f.py. Kept as fallback because the
    #      vendored v2 DB predates post-2006 kernels.
    #   3. TTL bucket (linux / windows / embedded). Coarse but never
    #      lies when at least one TCP packet was seen.
    os_guess: str | None = None
    modal_ttl = Counter(ttl_values).most_common(1)[0][0] if ttl_values else None

    osfp_match = _match_via_osfp_providers(tcp_fp, modal_ttl, tcp_fp_context)
    if osfp_match is not None:
        # Render "Linux" + "2.6.x kernel" as "Linux 2.6.x kernel" — a single
        # string fits the existing os_guess column contract. Flavor can be
        # empty for generic signatures, in which case we just emit the OS.
        os_guess = osfp_match.os if not osfp_match.flavor else f"{osfp_match.os} {osfp_match.flavor}"
    elif os_guesses:
        os_guess = Counter(os_guesses).most_common(1)[0][0]
    elif modal_ttl is not None:
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
