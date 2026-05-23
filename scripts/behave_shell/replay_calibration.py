# SPDX-License-Identifier: AGPL-3.0-or-later
"""Replay one calibration-corpus shard through the BEHAVE-SHELL handler.

Phase 6 smoke helper. Drives the production handler
(``decnet.profiler.behave_shell._handler.handle_session_ended``)
against an asciinema shard from
``BEHAVE/prototype_extractors/shell/`` *without* a live decky.
Mints a temp SQLite repo, an Attacker row, and an
``attacker.session.ended``-shape payload, then calls the handler
exactly the way the worker does.

This is **not** a substitute for the manual decky run described in
``scripts/behave_shell/README.md`` — the integration doc's Phase 6
calls for a real PTY round-trip. This helper exercises the handler +
storage layer end-to-end without the worker loop, so a failure here
points at the engine and not at the bus / collector / disk-reach
plumbing.

Usage::

    python scripts/behave_shell/replay_calibration.py \\
        --shard /path/to/sessions-2026-05-02.jsonl \\
        --label HUMAN

Exit codes:
    0  every session in the shard produced ≥ 1 observation
    1  zero observations produced for at least one session
    2  argument / IO error
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import json
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from decnet.profiler.behave_shell._handler import handle_session_ended
from decnet.web.db.factory import get_repository


def _sids_in_shard(shard: Path) -> list[str]:
    sids: list[str] = []
    seen: set[str] = set()
    with shard.open() as f:
        for line in f:
            try:
                rec = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if not isinstance(rec, dict):
                continue
            sid = rec.get("sid")
            if not isinstance(sid, str) or sid in seen:
                continue
            seen.add(sid)
            sids.append(sid)
    return sids


async def _seed_attacker(repo: Any, ip: str) -> str:
    return await repo.upsert_attacker({
        "ip": ip,
        "first_seen": datetime.now(timezone.utc),
        "last_seen": datetime.now(timezone.utc),
        "event_count": 1,
        "service_count": 1,
        "decky_count": 1,
        "services": "[\"ssh\"]",
        "deckies": "[\"smoke-decky\"]",
        "traversal_path": None,
        "is_traversal": False,
        "bounty_count": 0,
        "credential_count": 0,
        "fingerprints": "[]",
        "commands": "[]",
        "country_code": None,
        "country_source": None,
        "asn": None,
        "as_name": None,
        "asn_source": None,
        "updated_at": datetime.now(timezone.utc),
    })


def _payload_for(shard: Path, sid: str, ip: str) -> dict[str, Any]:
    return {
        "session_id": sid,
        "attacker_uuid": None,
        "attacker_ip": ip,
        "decky_id": "smoke-decky",
        "service": "ssh",
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "duration_s": 0.0,
        "commands": [],
        "shard_path": str(shard),
    }


async def _replay(shard: Path, label: str) -> int:
    sids = _sids_in_shard(shard)
    if not sids:
        print(f"[{label}] FAIL — no sids found in shard", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="behave-smoke.") as tmp:
        db_path = Path(tmp) / "smoke.db"
        repo = get_repository(db_path=str(db_path))
        await repo.initialize()

        bus_events: list[tuple[str, dict[str, Any], str]] = []

        def _publish(topic: str, payload: dict[str, Any], event_type: str) -> None:
            bus_events.append((topic, payload, event_type))

        per_sid_counts: dict[str, int] = {}
        per_sid_primitives: dict[str, collections.Counter] = {}
        for sid in sids:
            ip = f"10.{abs(hash(sid)) % 256}.{abs(hash(sid + label)) % 256}.5"
            await _seed_attacker(repo, ip)
            n = await handle_session_ended(repo, _payload_for(shard, sid, ip), _publish)
            per_sid_counts[sid] = n
            per_sid_primitives[sid] = collections.Counter()

        # Snapshot the observations table for each sid via evidence_ref.
        all_primitives: collections.Counter[str] = collections.Counter()
        for topic, payload, _etype in bus_events:
            primitive = payload.get("primitive") or topic.split(".", 2)[2]
            all_primitives[primitive] += 1

        total_obs = sum(per_sid_counts.values())
        empty_sids = [sid for sid, n in per_sid_counts.items() if n == 0]

        print(f"[{label}] sessions={len(sids)} observations={total_obs} "
              f"distinct_primitives={len(all_primitives)} bus_events={len(bus_events)}")
        if empty_sids:
            print(f"[{label}] FAIL — {len(empty_sids)}/{len(sids)} sessions emitted "
                  f"zero observations", file=sys.stderr)
            for sid in empty_sids[:3]:
                print(f"[{label}]   empty sid={sid}", file=sys.stderr)
            return 1
        # One-line top-5 primitive sample for visual sanity.
        top = ", ".join(
            f"{p}={c}" for p, c in all_primitives.most_common(5)
        )
        print(f"[{label}] top: {top}")
        return 0


async def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", required=True, type=Path,
                        help="Path to a sessions-YYYY-MM-DD.jsonl shard")
    parser.add_argument("--label", required=True,
                        help="Calibration class label (HUMAN / YOU-sim / "
                             "LW-sim / CLAUDE-FF / CLAUDE-CL)")
    args = parser.parse_args()
    if not args.shard.is_file():
        print(f"shard not a file: {args.shard}", file=sys.stderr)
        return 2
    return await _replay(args.shard, args.label)


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
