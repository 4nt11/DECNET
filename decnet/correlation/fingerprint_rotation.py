"""Attacker substrate-fingerprint rotation detection.

Called inline from the prober at each fingerprint emit site.  Looks up
the last persisted hash for ``(attacker_uuid, port, probe_type)``;
when the new hash differs from the last one, emits a derived
``attacker.fingerprint_rotated`` event (bus + RFC 5424 syslog) and
stamps the ``Attacker`` row's rotation telemetry.

This is a pure library — no daemon, no async loop.  The prober is the
only producer.  We just teach it to derive a second event on hash
flip without standing up another worker (DEBT-032).
"""
from __future__ import annotations

import uuid as _uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Literal

from sqlmodel import Session, select

from decnet.web.db.models import Attacker, AttackerFingerprintState

ProbeType = Literal["jarm", "hassh", "tcpfp"]
RotationKind = Literal[
    "no_attacker_row",  # caller raced ahead of correlator; skip silently
    "first_sighting",   # state row created, no prior hash
    "unchanged",        # same hash as last sighting
    "rotated",          # hash differs; event emitted, Attacker stamped
]

PublishFn = Callable[[str, dict[str, Any]], None]
SyslogFn = Callable[[str, dict[str, Any]], None]


@dataclass
class RotationOutcome:
    """Return shape of :func:`record_fingerprint`.  Caller usually
    ignores it; useful for tests + tracing."""
    kind: RotationKind
    old_hash: str | None
    new_hash: str
    rotation_count: int


_ROTATED_EVENT_TYPE = "attacker.fingerprint_rotated"


def record_fingerprint(
    session: Session,
    *,
    attacker_ip: str,
    port: int,
    probe_type: ProbeType,
    new_hash: str,
    ts: datetime,
    publish_fn: PublishFn | None = None,
    syslog_fn: SyslogFn | None = None,
) -> RotationOutcome:
    """Upsert state row; on hash diff, emit derived event + stamp.

    Resolves ``attacker_uuid`` from ``attacker_ip`` via the existing
    Attacker table.  If no Attacker row exists yet (the prober raced
    ahead of the correlator), returns ``kind="no_attacker_row"`` and
    does nothing — the next probe cycle will pick it up once the
    correlator has caught up.

    State upsert + Attacker stamp + publish + syslog are committed in
    one transaction so a partial failure can't desync state from
    what was emitted.
    """
    attacker = session.exec(
        select(Attacker).where(Attacker.ip == attacker_ip)
    ).first()
    if attacker is None:
        return RotationOutcome(
            kind="no_attacker_row",
            old_hash=None,
            new_hash=new_hash,
            rotation_count=0,
        )

    row = session.exec(
        select(AttackerFingerprintState).where(
            AttackerFingerprintState.attacker_uuid == attacker.uuid,
            AttackerFingerprintState.port == port,
            AttackerFingerprintState.probe_type == probe_type,
        )
    ).first()

    if row is None:
        session.add(AttackerFingerprintState(
            uuid=str(_uuid.uuid4()),
            attacker_uuid=attacker.uuid,
            port=port,
            probe_type=probe_type,
            last_hash=new_hash,
            last_seen=ts,
            rotation_count=0,
        ))
        session.commit()
        return RotationOutcome(
            kind="first_sighting",
            old_hash=None,
            new_hash=new_hash,
            rotation_count=0,
        )

    if row.last_hash == new_hash:
        row.last_seen = ts
        session.add(row)
        session.commit()
        return RotationOutcome(
            kind="unchanged",
            old_hash=row.last_hash,
            new_hash=new_hash,
            rotation_count=row.rotation_count,
        )

    old_hash = row.last_hash
    row.last_hash = new_hash
    row.last_seen = ts
    row.rotation_count += 1
    session.add(row)

    attacker.rotation_count += 1
    attacker.last_rotation_at = ts
    session.add(attacker)

    payload: dict[str, Any] = {
        "attacker_uuid": attacker.uuid,
        "attacker_ip": attacker_ip,
        "port": port,
        "probe_type": probe_type,
        "old_hash": old_hash,
        "new_hash": new_hash,
        "rotation_count": row.rotation_count,
        "ts": ts.isoformat(),
    }

    if publish_fn is not None:
        publish_fn(_ROTATED_EVENT_TYPE, payload)
    if syslog_fn is not None:
        syslog_fn(_ROTATED_EVENT_TYPE, payload)

    session.commit()

    return RotationOutcome(
        kind="rotated",
        old_hash=old_hash,
        new_hash=new_hash,
        rotation_count=row.rotation_count,
    )
