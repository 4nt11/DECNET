"""Agent-side sqlite cache of the currently-applied topology.

**This is a cache, not a source of truth.**  The master is the only
authority for what the agent should be running.  This store exists so
the agent can answer two questions quickly and offline:

1. What topology did I last apply, and with what version hash?
2. Is what docker is currently doing consistent with that?

The hash goes out on every heartbeat; the master compares it to what
it thinks this host should be running and schedules a re-push on
mismatch.

Why sqlite when the blob is JSON?  Consistent with
:mod:`decnet.swarm.log_forwarder._OffsetStore` — single-row sqlite is
the project-wide pattern for agent-local persistent state.  Keeps
operational mental model small: "one state.db per thing".

Design choices worth calling out:

- **One row, one topology.**  v1 only supports a single topology per
  agent.  Attempting to :meth:`put` a different ``topology_id`` while
  a row already exists raises :class:`AlreadyApplied` — the agent
  rejects the apply with 409 and the master is expected to teardown
  the old one first.
- **No auto-restore on boot.**  The agent does NOT read this db at
  startup and try to re-apply.  Whatever docker has after a restart
  is what it has; the next heartbeat reports the truth and the
  master decides whether to re-push.  Same reason we don't sync
  mutations from agent → master anywhere else: split-brain is worse
  than temporary drift.
"""
from __future__ import annotations

import json
import pathlib
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Optional


class AlreadyApplied(RuntimeError):
    """Raised when a different topology is already pinned to this agent."""


@dataclass(frozen=True)
class AppliedRow:
    topology_id: str
    applied_version_hash: str
    hydrated: dict[str, Any]
    applied_at: int
    last_error: Optional[str]


class TopologyStore:
    """Single-row sqlite cache. Stdlib only, sync (called from endpoints)."""

    def __init__(self, db_path: pathlib.Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: Starlette/FastAPI runs sync endpoint
        # bodies on a worker thread distinct from where `app` is imported.
        # The agent is single-process, so there's no real contention —
        # sqlite's own connection lock is enough.
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS applied_topology ("
            " topology_id TEXT PRIMARY KEY,"
            " applied_version_hash TEXT NOT NULL,"
            " hydrated_blob_json TEXT NOT NULL,"
            " applied_at INTEGER NOT NULL,"
            " last_error TEXT)"
        )
        self._conn.commit()

    # ----------------------------------------------------------------- reads

    def current(self) -> Optional[AppliedRow]:
        """Return the single applied topology, or ``None`` if idle."""
        row = self._conn.execute(
            "SELECT topology_id, applied_version_hash, hydrated_blob_json,"
            " applied_at, last_error FROM applied_topology LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return AppliedRow(
            topology_id=row["topology_id"],
            applied_version_hash=row["applied_version_hash"],
            hydrated=json.loads(row["hydrated_blob_json"]),
            applied_at=int(row["applied_at"]),
            last_error=row["last_error"],
        )

    # ---------------------------------------------------------------- writes

    def put(
        self,
        topology_id: str,
        applied_version_hash: str,
        hydrated: dict[str, Any],
    ) -> None:
        """Record an applied topology.

        If a *different* topology is already recorded, raises
        :class:`AlreadyApplied`.  Re-applying the same ``topology_id``
        just updates the hash + blob (idempotent re-push).
        """
        existing = self.current()
        if existing is not None and existing.topology_id != topology_id:
            raise AlreadyApplied(
                f"agent already has topology {existing.topology_id!r}; "
                f"cannot apply {topology_id!r}"
            )
        self._conn.execute(
            "INSERT INTO applied_topology"
            " (topology_id, applied_version_hash, hydrated_blob_json,"
            "  applied_at, last_error)"
            " VALUES (?, ?, ?, ?, NULL)"
            " ON CONFLICT(topology_id) DO UPDATE SET"
            "  applied_version_hash=excluded.applied_version_hash,"
            "  hydrated_blob_json=excluded.hydrated_blob_json,"
            "  applied_at=excluded.applied_at,"
            "  last_error=NULL",
            (
                topology_id,
                applied_version_hash,
                json.dumps(hydrated, sort_keys=True),
                int(time.time()),
            ),
        )
        self._conn.commit()

    def record_error(
        self,
        topology_id: str,
        message: str,
        hydrated: Optional[dict[str, Any]] = None,
    ) -> None:
        """Attach a last-error message for *topology_id*.

        Upserts a marker row when no apply has yet succeeded for this
        topology — that way a failure *during* the first materialise
        (put() hasn't been reached) still surfaces via GET
        /topology/state and the next heartbeat.  The marker row uses an
        empty ``applied_version_hash`` so master's heartbeat check sees
        the hash mismatch and schedules a resync.

        If *hydrated* is provided it is stored so a later teardown can
        still walk the LAN list — otherwise a partial deploy is strands
        containers + bridges with no breadcrumb back to them.
        """
        blob = json.dumps(hydrated, sort_keys=True) if hydrated else "{}"
        self._conn.execute(
            "INSERT INTO applied_topology"
            " (topology_id, applied_version_hash, hydrated_blob_json,"
            "  applied_at, last_error)"
            " VALUES (?, '', ?, 0, ?)"
            " ON CONFLICT(topology_id) DO UPDATE SET"
            "  last_error=excluded.last_error,"
            "  hydrated_blob_json=CASE"
            "   WHEN applied_topology.hydrated_blob_json='{}'"
            "   THEN excluded.hydrated_blob_json"
            "   ELSE applied_topology.hydrated_blob_json END",
            (topology_id, blob, message),
        )
        self._conn.commit()

    def clear(self, topology_id: str) -> None:
        """Remove the row for *topology_id* (post-teardown).

        No-op if the row doesn't exist — makes teardown idempotent.
        """
        self._conn.execute(
            "DELETE FROM applied_topology WHERE topology_id=?",
            (topology_id,),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


# --------------------------------------------------- live docker observation


def observed(docker_client: Any) -> dict[str, Any]:
    """Snapshot what docker is *actually* running on this agent.

    Returns a compact dict the heartbeat can ship so the master can
    cross-check ``applied_version_hash`` against reality (a matching
    hash with missing bridges is still drift).  Best-effort: if docker
    is unreachable we return an ``error`` marker rather than raising —
    the agent still needs to heartbeat, and the master can treat
    ``error`` as "unknown, re-push".
    """
    try:
        bridges = [
            n.name
            for n in docker_client.networks.list()
            if n.attrs.get("Driver") == "bridge"
            and n.name.startswith("decnet-topology-")
        ]
        containers = [
            c.name
            for c in docker_client.containers.list(all=False)
            if c.name.startswith("decnet-")
        ]
        return {"bridges": sorted(bridges), "containers": sorted(containers)}
    except Exception as exc:  # noqa: BLE001 — best-effort observation
        return {"error": str(exc)[:200]}


__all__ = ["TopologyStore", "AppliedRow", "AlreadyApplied", "observed"]
