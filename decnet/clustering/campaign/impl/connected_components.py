"""Connected-components campaign clusterer (v1).

Builds a similarity graph over identities (the layer below — already
clustered from raw observations), runs union-find over edges that pass
:data:`CAMPAIGN_EDGE_THRESHOLD`, and writes one ``campaigns`` row per
component.

Mirror of :mod:`decnet.clustering.impl.connected_components` for the
layer above. Same revocable-merge discipline: identities stay FK'd to
their original campaign row throughout, soft pointers via
``campaigns.merged_into_uuid``.

**Time-agnostic.** Edges depend only on pairwise relative offsets —
fixture F7 (slow_burn) invariant carries forward to this layer.
"""
from __future__ import annotations

import json
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from decnet.clustering.campaign.base import (
    CampaignClusterer,
    CampaignClusterResult,
)
from decnet.clustering.campaign.impl.similarity import (
    CAMPAIGN_EDGE_THRESHOLD,
    IdentityFeatures,
    combined_campaign_weight,
)
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

log = get_logger("clustering.campaign.connected_components")


def cluster_identities(
    features: Iterable[IdentityFeatures],
) -> dict[str, str]:
    """Run connected-components over the campaign-level similarity graph.

    Pure: no DB, no clock, no I/O. Returns ``{identity_uuid: cluster_id}``.
    Singletons get a stable per-identity cluster id; cluster ids are
    opaque strings.
    """
    feat_list = list(features)
    parent: dict[str, str] = {f.identity_uuid: f.identity_uuid for f in feat_list}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    for i, a in enumerate(feat_list):
        for b in feat_list[i + 1:]:
            if combined_campaign_weight(a, b) >= CAMPAIGN_EDGE_THRESHOLD:
                union(a.identity_uuid, b.identity_uuid)

    return {f.identity_uuid: f"cmp-{find(f.identity_uuid)}" for f in feat_list}


def from_identity_row(row: dict[str, Any]) -> IdentityFeatures:
    """Project an ``AttackerIdentity`` projection row dict into an
    :class:`IdentityFeatures`.

    ``row`` is the shape returned by
    ``BaseRepository.list_identities_for_clustering``: uuid +
    ja3_hashes / hassh_hashes / payload_simhashes / c2_endpoints
    (JSON list[str] or null).

    Phase-handoff fields stay empty until the production-row adapter
    learns to mine logs for per-decky phase sequences (TODO.md
    "production-side payload + C2 + commands joins"). Without those,
    the campaign clusterer falls back to shared-infra + temporal
    overlap + cohort signals on production data; the fixture path
    exercises the full feature set via :func:`from_synthetic_identity`.
    """
    payload_hashes = _parse_json_list(row.get("payload_simhashes"))
    c2_endpoints = _parse_json_list(row.get("c2_endpoints"))

    return IdentityFeatures(
        identity_uuid=row["uuid"],
        payload_hashes=frozenset(payload_hashes),
        c2_endpoints=frozenset(c2_endpoints),
    )


def _parse_json_list(raw: Optional[str]) -> list[str]:
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(decoded, list):
        return []
    return [str(x) for x in decoded if x is not None]


class ConnectedComponentsCampaignClusterer(CampaignClusterer):
    """Connected-components campaign clusterer."""

    name = "connected_components"

    async def tick(self, repo: BaseRepository) -> CampaignClusterResult:
        try:
            rows = await repo.list_identities_for_clustering()
        except Exception:  # noqa: BLE001
            log.exception("campaign clusterer: failed to read identities")
            return CampaignClusterResult()

        if not rows:
            return CampaignClusterResult()

        # Pre-compute the campaign merge chain so an identity's
        # "effective" campaign follows merged_into_uuid up to the winner.
        try:
            all_campaigns = await repo.list_all_campaigns()
        except Exception:  # noqa: BLE001
            log.exception("campaign clusterer: failed to read campaigns")
            return CampaignClusterResult()
        campaign_chain = _build_merge_chain(all_campaigns)

        # Project + cluster.  Skip identities that are themselves
        # merged out — their winner is the active row and gets clustered
        # on its own.  This keeps the campaign graph from double-counting.
        active_rows = [r for r in rows if not r.get("merged_into_uuid")]
        feature_list: list[IdentityFeatures] = [
            from_identity_row(r) for r in active_rows
        ]
        row_by_uuid: dict[str, dict[str, Any]] = {
            r["uuid"]: r for r in active_rows
        }
        labels = cluster_identities(feature_list)

        # Group identities by predicted cluster.
        components: dict[str, list[str]] = {}
        for identity_uuid, cluster_id in labels.items():
            components.setdefault(cluster_id, []).append(identity_uuid)

        result = CampaignClusterResult()
        now = datetime.now(timezone.utc)

        # Pass 1 — per-component reconciliation: form, link, merge.
        for member_ids in components.values():
            literal_campaign_ids = {
                row_by_uuid[m]["campaign_id"] for m in member_ids
                if row_by_uuid[m].get("campaign_id")
            }
            effective_ids = {
                campaign_chain.get(c, c) for c in literal_campaign_ids
            }
            unassigned = [
                m for m in member_ids
                if not row_by_uuid[m].get("campaign_id")
            ]

            if not effective_ids:
                campaign_uuid = str(_uuid.uuid4())
                try:
                    await repo.create_campaign({
                        "uuid": campaign_uuid,
                        "schema_version": 1,
                        "first_seen_at": now,
                        "last_seen_at": now,
                        "created_at": now,
                        "updated_at": now,
                        "identity_count": len(member_ids),
                    })
                except Exception:  # noqa: BLE001
                    log.exception(
                        "campaign clusterer: failed to create campaign for "
                        "component %s", member_ids,
                    )
                    continue

                linked: list[str] = []
                for identity_uuid in member_ids:
                    if await _link(repo, identity_uuid, campaign_uuid):
                        linked.append(identity_uuid)
                if linked:
                    result.campaigns_formed.append({
                        "campaign_uuid": campaign_uuid,
                        "identity_uuids": linked,
                    })
                continue

            winner_uuid = min(effective_ids)
            losers = effective_ids - {winner_uuid}

            for loser_uuid in losers:
                try:
                    await repo.update_campaign_merged_into(
                        loser_uuid, winner_uuid,
                    )
                except Exception:  # noqa: BLE001
                    log.exception(
                        "campaign clusterer: failed to merge %s -> %s",
                        loser_uuid, winner_uuid,
                    )
                    continue
                campaign_chain[loser_uuid] = winner_uuid
                result.campaigns_merged.append({
                    "winner_uuid": winner_uuid,
                    "loser_uuid": loser_uuid,
                })

            for identity_uuid in unassigned:
                if await _link(repo, identity_uuid, winner_uuid):
                    result.identities_assigned.append({
                        "campaign_uuid": winner_uuid,
                        "identity_uuid": identity_uuid,
                        "prior_campaign_uuid": None,
                    })

        # Pass 2 — revocable-merge undo for campaigns. Same shape as
        # the identity-side check: if a merged-out campaign's
        # identities no longer cluster with the winner's, revoke.
        identities_by_literal_campaign: dict[str, list[str]] = {}
        for identity_uuid, r in row_by_uuid.items():
            cid = r.get("campaign_id")
            if cid:
                identities_by_literal_campaign.setdefault(cid, []).append(
                    identity_uuid,
                )

        for campaign_row in all_campaigns:
            if not campaign_row.get("merged_into_uuid"):
                continue
            loser_uuid = campaign_row["uuid"]
            winner_uuid = campaign_chain.get(loser_uuid, loser_uuid)
            if winner_uuid == loser_uuid:
                continue
            loser_idents = identities_by_literal_campaign.get(loser_uuid, [])
            winner_idents = identities_by_literal_campaign.get(winner_uuid, [])
            if not loser_idents or not winner_idents:
                continue
            loser_clusters = {labels[i] for i in loser_idents if i in labels}
            winner_clusters = {labels[i] for i in winner_idents if i in labels}
            if loser_clusters & winner_clusters:
                continue
            try:
                await repo.update_campaign_merged_into(loser_uuid, None)
            except Exception:  # noqa: BLE001
                log.exception(
                    "campaign clusterer: failed to unmerge %s from %s",
                    loser_uuid, winner_uuid,
                )
                continue
            campaign_chain[loser_uuid] = loser_uuid
            result.campaigns_unmerged.append({
                "resurrected_uuid": loser_uuid,
                "former_winner_uuid": winner_uuid,
            })

        return result


def _build_merge_chain(
    rows: list[dict[str, Any]],
) -> dict[str, str]:
    _MAX_HOPS = 8
    by_uuid: dict[str, dict[str, Any]] = {r["uuid"]: r for r in rows}
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
    repo: BaseRepository, identity_uuid: str, campaign_uuid: str,
) -> bool:
    try:
        await repo.set_identity_campaign_id(identity_uuid, campaign_uuid)
        return True
    except Exception:  # noqa: BLE001
        log.exception(
            "campaign clusterer: failed to link identity=%s -> campaign=%s",
            identity_uuid, campaign_uuid,
        )
        return False


__all__ = [
    "ConnectedComponentsCampaignClusterer",
    "cluster_identities",
    "from_identity_row",
]
