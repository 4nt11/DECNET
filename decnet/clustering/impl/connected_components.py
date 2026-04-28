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

The clusterer assigns identities to NULL observations, merges existing
identities when a single predicted component spans them, and revokes
prior merges when the predicted component splits a merged-out identity
away from its winner. Observations stay FK'd to their original identity
row throughout — merges are soft pointers via
``attacker_identities.merged_into_uuid``, never observation re-points.
That keeps the audit trail intact and lets cached subscribers resolve
merged-out UUIDs through the chain.
"""
from __future__ import annotations

import json
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from decnet.clustering.base import Clusterer, ClusterResult
from decnet.clustering.impl.similarity import (
    EDGE_THRESHOLD,
    Observation,
    combined_edge_weight,
)
from decnet.logging import get_logger
from decnet.profiler.identity_rollup import extract_fp_summaries
from decnet.web.db.repository import BaseRepository

log = get_logger("clustering.connected_components")


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
            if combined_edge_weight(a, b) >= EDGE_THRESHOLD:
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

        # Build the merge chain so a row's "effective" identity follows
        # merged_into_uuid up to the canonical winner. Pre-computing it
        # lets us reason about post-merge identity membership in one
        # place. ``identity_chain[u]`` is the canonical winner for
        # identity ``u`` (or ``u`` itself if not merged out).
        try:
            all_identities = await repo.list_all_identities()
        except Exception:  # noqa: BLE001
            log.exception("clusterer: failed to read identities")
            return ClusterResult()
        identity_chain = _build_merge_chain(all_identities)

        # Project + cluster.
        observations: list[Observation] = []
        row_by_id: dict[str, dict[str, Any]] = {}
        for r in rows:
            obs = from_attacker_row(r)
            observations.append(obs)
            row_by_id[obs.observation_id] = r
        labels = cluster_observations(observations)

        # Group observations by predicted cluster.
        components: dict[str, list[str]] = {}
        for obs_id, cluster_id in labels.items():
            components.setdefault(cluster_id, []).append(obs_id)

        result = ClusterResult()
        now = datetime.now(timezone.utc)

        # Pass 1 — per-component reconciliation: form, link, merge.
        for member_ids in components.values():
            literal_ids = {
                row_by_id[m]["identity_id"] for m in member_ids
                if row_by_id[m].get("identity_id")
            }
            effective_ids = {identity_chain.get(i, i) for i in literal_ids}
            unassigned = [
                m for m in member_ids
                if not row_by_id[m].get("identity_id")
            ]

            if not effective_ids:
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
                    if await _link(repo, obs_id, identity_uuid):
                        linked.append(obs_id)
                if linked:
                    result.identities_formed.append({
                        "identity_uuid": identity_uuid,
                        "observation_uuids": linked,
                    })
                await _roll_up_fingerprints(
                    repo, identity_uuid, [row_by_id[m] for m in member_ids],
                )
                continue

            # Deterministic winner so two clusterer runs produce the
            # same merge direction. Sorting by uuid string is stable
            # and doesn't depend on row insertion order.
            winner_uuid = min(effective_ids)
            losers = effective_ids - {winner_uuid}

            for loser_uuid in losers:
                try:
                    await repo.update_identity_merged_into(loser_uuid, winner_uuid)
                except Exception:  # noqa: BLE001
                    log.exception(
                        "clusterer: failed to merge %s -> %s",
                        loser_uuid, winner_uuid,
                    )
                    continue
                identity_chain[loser_uuid] = winner_uuid
                result.identities_merged.append({
                    "winner_uuid": winner_uuid,
                    "loser_uuid": loser_uuid,
                })

            # Link any unassigned observations in the component to the
            # winner so a subsequent tick sees a single-identity
            # component and skips this branch entirely.
            for obs_id in unassigned:
                if await _link(repo, obs_id, winner_uuid):
                    result.observations_linked.append({
                        "identity_uuid": winner_uuid,
                        "observation_uuid": obs_id,
                    })

            # Re-roll the winner's fingerprint summary across every
            # observation now in this component (including the loser
            # side — the merge unifies their evidence even though the
            # loser's identity row stays FK'd via merged_into_uuid).
            await _roll_up_fingerprints(
                repo, winner_uuid, [row_by_id[m] for m in member_ids],
            )

        # Pass 2 — revocable-merge undo. For each currently-merged-out
        # identity, check whether its observations still cluster with
        # the winner's. If not, the merge is contradicted by new
        # evidence — clear merged_into_uuid and emit identity.unmerged.
        # Observations FK'd to the resurrected loser stay where they
        # were; the chain just stops following.
        observations_by_literal_identity: dict[str, list[str]] = {}
        for obs_id, r in row_by_id.items():
            iid = r.get("identity_id")
            if iid:
                observations_by_literal_identity.setdefault(iid, []).append(obs_id)

        for identity_row in all_identities:
            if not identity_row.get("merged_into_uuid"):
                continue
            loser_uuid = identity_row["uuid"]
            winner_uuid = identity_chain.get(loser_uuid, loser_uuid)
            if winner_uuid == loser_uuid:
                continue  # broken chain — paranoia
            loser_obs = observations_by_literal_identity.get(loser_uuid, [])
            winner_obs = observations_by_literal_identity.get(winner_uuid, [])
            if not loser_obs or not winner_obs:
                # No observations either side — can't disprove the merge.
                continue
            loser_clusters = {labels[o] for o in loser_obs}
            winner_clusters = {labels[o] for o in winner_obs}
            if loser_clusters & winner_clusters:
                continue  # still co-clustered with winner — merge stands
            try:
                await repo.update_identity_merged_into(loser_uuid, None)
            except Exception:  # noqa: BLE001
                log.exception(
                    "clusterer: failed to unmerge %s from %s",
                    loser_uuid, winner_uuid,
                )
                continue
            identity_chain[loser_uuid] = loser_uuid
            result.identities_unmerged.append({
                "resurrected_uuid": loser_uuid,
                "former_winner_uuid": winner_uuid,
            })

        return result


def _build_merge_chain(
    identities: list[dict[str, Any]],
) -> dict[str, str]:
    """Build a uuid → canonical-winner map from a list of identity rows.

    Follows ``merged_into_uuid`` to a fixed point per identity, with a
    hop cap to defend against accidental cycles. The returned dict
    contains an entry for every identity uuid (mapping to itself if
    not merged out).
    """
    _MAX_HOPS = 8
    by_uuid: dict[str, dict[str, Any]] = {i["uuid"]: i for i in identities}
    chain: dict[str, str] = {}
    for uuid_ in by_uuid:
        cur = uuid_
        for _ in range(_MAX_HOPS):
            row = by_uuid.get(cur)
            if row is None:
                break
            nxt = row.get("merged_into_uuid")
            if not nxt or nxt == cur:
                break
            cur = nxt
        chain[uuid_] = cur
    return chain


async def _link(
    repo: BaseRepository, observation_uuid: str, identity_uuid: str,
) -> bool:
    """Set ``attackers.identity_id`` and return ``True`` on success.

    Wraps the repo call so the tick body stays linear and exception
    handling is consistent across the form / link / merge branches.
    """
    try:
        await repo.set_attacker_identity_id(observation_uuid, identity_uuid)
        return True
    except Exception:  # noqa: BLE001
        log.exception(
            "clusterer: failed to link obs=%s -> identity=%s",
            observation_uuid, identity_uuid,
        )
        return False


async def _roll_up_fingerprints(
    repo: BaseRepository,
    identity_uuid: str,
    member_rows: list[dict[str, Any]],
) -> None:
    """Project member observations' fingerprint blobs onto the identity's
    summary columns. Best-effort: a write failure is logged but never
    breaks the clusterer tick — the columns just stay stale until the
    next pass."""
    summaries = extract_fp_summaries(member_rows)
    try:
        await repo.update_identity_fingerprints(identity_uuid, **summaries)
    except Exception:  # noqa: BLE001
        log.exception(
            "clusterer: failed to roll up fingerprints for identity=%s",
            identity_uuid,
        )


__all__ = [
    "ConnectedComponentsClusterer",
    "cluster_observations",
    "from_attacker_row",
]
