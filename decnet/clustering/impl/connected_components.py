"""Connected-components identity clusterer (v1).

Builds a similarity graph over observations (per-IP attacker rows),
runs union-find over edges that pass a confidence threshold, and writes
one ``attacker_identities`` row per component.

**v1 signal coverage (this commit):**

* High-weight tier: JA3 / HASSH / payload-hash / C2-endpoint exact
  match (alone enough to cluster). The production tick currently sees
  JA3 + HASSH only — payload + C2 require log mining and join in
  later commits. The fixture tests exercise the full high-weight set
  through the in-memory path.

Subsequent commits add medium / low / very-low tier edges, phase-
handoff edges, and revocable merges. Edges MUST stay time-agnostic
— fixture 7 forbids recency-decay clustering.

**v1 behavior:**

The clusterer only assigns identities to observations whose
``identity_id`` is currently NULL. Observations already linked to an
identity are read-only this pass (they still participate in graph
edges, so a new observation can join an existing identity, but the
clusterer never reassigns or merges existing identities). Reassignment
+ merging land in commit 10 alongside revocable merges.
"""
from __future__ import annotations

import json
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from decnet.clustering.base import Clusterer, ClusterResult
from decnet.clustering.impl.similarity import (
    Observation,
    high_weight_edge,
)
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

log = get_logger("clustering.connected_components")


# Threshold above which an edge survives into the graph. The high-tier
# functions return 1.0 on agreement, so a literal >= 1.0 cutoff means
# "exact match required." Once medium-tier edges combine, this becomes
# a tunable.
_EDGE_THRESHOLD = 1.0


def cluster_observations(
    observations: Iterable[Observation],
) -> dict[str, str]:
    """Run connected-components over the high-weight similarity graph.

    Pure: no DB, no clock, no I/O. Both the fixture-validation tests
    and the production ``tick`` consume this. The mapping is a
    deterministic function of the input set + edge function.

    Singletons get a stable per-observation cluster id so callers can
    distinguish "isolated observation" from "merged into nothing."

    Returns ``{observation_id: cluster_id}``. Cluster ids are opaque
    strings — callers must not rely on their format.
    """
    obs_list = list(observations)
    parent: dict[str, str] = {o.observation_id: o.observation_id for o in obs_list}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    for i, a in enumerate(obs_list):
        for b in obs_list[i + 1:]:
            if high_weight_edge(a, b) >= _EDGE_THRESHOLD:
                union(a.observation_id, b.observation_id)

    # Roots: each unique find(o) is a component representative. Use
    # them as the cluster id so two runs over the same input produce
    # the same labels (handy for assertions).
    return {o.observation_id: f"cc-{find(o.observation_id)}" for o in obs_list}


def from_attacker_row(row: dict[str, Any]) -> Observation:
    """Project an ``Attacker`` row dict into an :class:`Observation`.

    Pulls JA3 / HASSH out of the ``Attacker.fingerprints`` JSON list
    (one entry per fingerprint event the prober collected). Multiple
    JA3s on a single observation are flattened to a single value —
    the most-recent — because :class:`Observation` is a single-row
    projection; an observation that exhibits two distinct JA3s across
    its lifetime is a wire-level oddity that the clusterer treats by
    keeping the latest. The identity row itself can store the full
    list across observations.

    Payload + C2 + commands are left empty — log mining lands in
    later commits. The function shape doesn't change when they do.
    """
    raw = row.get("fingerprints") or "[]"
    try:
        entries = json.loads(raw) if isinstance(raw, str) else list(raw)
    except (TypeError, ValueError):
        entries = []

    ja3: Optional[str] = None
    hassh: Optional[str] = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        h = entry.get("hash") or entry.get("value")
        if not h:
            continue
        if kind == "ja3":
            ja3 = h
        elif kind == "hassh":
            hassh = h

    return Observation(
        observation_id=row["uuid"],
        ja3=ja3,
        hassh=hassh,
        asn=row.get("asn"),
    )


class ConnectedComponentsClusterer(Clusterer):
    """Connected-components clusterer over the similarity graph.

    See module docstring for v1 signal coverage and behavior notes.
    """

    name = "connected_components"

    async def tick(self, repo: BaseRepository) -> ClusterResult:
        try:
            rows = await repo.list_attackers_for_clustering()
        except Exception:  # noqa: BLE001
            log.exception("clusterer: failed to read attackers")
            return ClusterResult()

        if not rows:
            return ClusterResult()

        # Project + cluster.
        observations: list[Observation] = []
        row_by_id: dict[str, dict[str, Any]] = {}
        for r in rows:
            obs = from_attacker_row(r)
            observations.append(obs)
            row_by_id[obs.observation_id] = r
        labels = cluster_observations(observations)

        # Group by predicted cluster.
        components: dict[str, list[str]] = {}
        for obs_id, cluster_id in labels.items():
            components.setdefault(cluster_id, []).append(obs_id)

        result = ClusterResult()
        now = datetime.now(timezone.utc)

        for member_ids in components.values():
            existing_identities = {
                row_by_id[m]["identity_id"] for m in member_ids
                if row_by_id[m].get("identity_id")
            }
            unassigned = [
                m for m in member_ids
                if not row_by_id[m].get("identity_id")
            ]

            if len(existing_identities) > 1:
                # Multi-identity component — merging lands in commit 10
                # (revocable merges). Skip for now; new observations in
                # this component stay unassigned this pass and will get
                # assigned once the merge logic exists.
                log.debug(
                    "clusterer: skipping component with %d existing identities "
                    "(merge lands in commit 10)", len(existing_identities),
                )
                continue

            if not unassigned:
                # Component is entirely already-assigned; nothing to do.
                continue

            if existing_identities:
                # Single existing identity → link the unassigned members.
                identity_uuid = next(iter(existing_identities))
                for obs_id in unassigned:
                    try:
                        await repo.set_attacker_identity_id(obs_id, identity_uuid)
                    except Exception:  # noqa: BLE001
                        log.exception(
                            "clusterer: failed to link obs=%s -> identity=%s",
                            obs_id, identity_uuid,
                        )
                        continue
                    result.observations_linked.append({
                        "identity_uuid": identity_uuid,
                        "observation_uuid": obs_id,
                    })
            else:
                # Fresh component — mint a new identity.
                identity_uuid = str(_uuid.uuid4())
                try:
                    await repo.create_attacker_identity({
                        "uuid": identity_uuid,
                        "schema_version": 1,
                        "first_seen_at": now,
                        "last_seen_at": now,
                        "created_at": now,
                        "updated_at": now,
                        "observation_count": len(member_ids),
                    })
                except Exception:  # noqa: BLE001
                    log.exception(
                        "clusterer: failed to create identity for component %s",
                        member_ids,
                    )
                    continue

                linked: list[str] = []
                for obs_id in member_ids:
                    try:
                        await repo.set_attacker_identity_id(obs_id, identity_uuid)
                    except Exception:  # noqa: BLE001
                        log.exception(
                            "clusterer: failed to link obs=%s -> identity=%s",
                            obs_id, identity_uuid,
                        )
                        continue
                    linked.append(obs_id)

                if linked:
                    result.identities_formed.append({
                        "identity_uuid": identity_uuid,
                        "observation_uuids": linked,
                    })

        return result


__all__ = [
    "ConnectedComponentsClusterer",
    "cluster_observations",
    "from_attacker_row",
]
