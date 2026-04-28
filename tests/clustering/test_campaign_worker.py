"""End-to-end tests for the campaign-clusterer worker shell + tick.

Mirrors :mod:`tests.clustering.test_clusterer_worker` for the layer
above. Covers shell lifecycle (shutdown / cancel / raising tick),
end-to-end ``tick`` against SQLite (form, link, merge, revoke), bus
fan-out to the four ``campaign.*`` topics + cross-family
``identity.campaign.assigned``, factory dispatch, and CLI gating.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest

from decnet.bus import topics as _topics
from decnet.clustering.campaign.base import (
    CampaignClusterer,
    CampaignClusterResult,
)
from decnet.clustering.campaign.factory import get_campaign_clusterer
from decnet.clustering.campaign.impl.connected_components import (
    ConnectedComponentsCampaignClusterer,
    cluster_identities,
    from_identity_row,
)
from decnet.clustering.campaign.impl.similarity import IdentityFeatures
from decnet.clustering.campaign.worker import run_campaign_clusterer_loop
from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "campaign.db"))
    await r.initialize()
    return r


@pytest.fixture(autouse=True)
def _no_bus(monkeypatch):
    """Run workers in poll-only mode — no real Unix socket."""
    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")


# ─── Test doubles ───────────────────────────────────────────────────────────


class _FakeClusterer(CampaignClusterer):
    name = "fake"

    def __init__(self, results=None) -> None:
        self._results = list(results or [])
        self.calls = 0

    async def tick(self, repo) -> CampaignClusterResult:
        self.calls += 1
        if self._results:
            return self._results.pop(0)
        return CampaignClusterResult()


class _RaisingClusterer(CampaignClusterer):
    name = "raising"

    def __init__(self) -> None:
        self.calls = 0

    async def tick(self, repo) -> CampaignClusterResult:
        self.calls += 1
        raise RuntimeError("boom")


# ─── Shell lifecycle ────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_loop_exits_on_shutdown(repo):
    shutdown = asyncio.Event()
    clusterer = _FakeClusterer()
    task = asyncio.create_task(
        run_campaign_clusterer_loop(
            repo, poll_interval_secs=0.05,
            clusterer=clusterer, shutdown=shutdown,
        )
    )
    await asyncio.sleep(0.12)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)
    assert clusterer.calls >= 1


@pytest.mark.anyio
async def test_loop_exits_on_cancel(repo):
    clusterer = _FakeClusterer()
    task = asyncio.create_task(
        run_campaign_clusterer_loop(
            repo, poll_interval_secs=0.05, clusterer=clusterer,
        )
    )
    await asyncio.sleep(0.1)
    task.cancel()
    await asyncio.wait_for(task, timeout=2.0)
    assert clusterer.calls >= 1


@pytest.mark.anyio
async def test_tick_failure_does_not_crash_loop(repo):
    shutdown = asyncio.Event()
    clusterer = _RaisingClusterer()
    task = asyncio.create_task(
        run_campaign_clusterer_loop(
            repo, poll_interval_secs=0.05,
            clusterer=clusterer, shutdown=shutdown,
        )
    )
    await asyncio.sleep(0.2)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)
    assert clusterer.calls >= 2


# ─── Bus fan-out ────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_publishes_campaign_result_on_bus(monkeypatch, repo):
    published: list[tuple[str, dict, str]] = []

    async def _fake_publish(bus, topic, payload, event_type=""):
        published.append((topic, payload, event_type))

    monkeypatch.setattr(
        "decnet.clustering.campaign.worker.publish_safely", _fake_publish,
    )

    result = CampaignClusterResult(
        campaigns_formed=[
            {"campaign_uuid": "c-1", "identity_uuids": ["i-1", "i-2"]},
        ],
        identities_assigned=[
            {"campaign_uuid": "c-1", "identity_uuid": "i-3",
             "prior_campaign_uuid": None},
        ],
        campaigns_merged=[
            {"winner_uuid": "c-1", "loser_uuid": "c-2"},
        ],
        campaigns_unmerged=[
            {"resurrected_uuid": "c-2", "former_winner_uuid": "c-1"},
        ],
    )
    clusterer = _FakeClusterer(results=[result])

    shutdown = asyncio.Event()
    task = asyncio.create_task(
        run_campaign_clusterer_loop(
            repo, poll_interval_secs=0.05,
            clusterer=clusterer, shutdown=shutdown,
        )
    )
    await asyncio.sleep(0.1)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)

    topics_seen = {t for t, _, _ in published}
    assert _topics.campaign(_topics.CAMPAIGN_FORMED) in topics_seen
    assert _topics.campaign(_topics.CAMPAIGN_IDENTITY_ASSIGNED) in topics_seen
    assert _topics.campaign(_topics.CAMPAIGN_MERGED) in topics_seen
    assert _topics.campaign(_topics.CAMPAIGN_UNMERGED) in topics_seen
    # Cross-family signal — every campaigns_formed identity AND every
    # identities_assigned identity should fire identity.campaign.assigned.
    cross = _topics.identity(_topics.IDENTITY_CAMPAIGN_ASSIGNED)
    cross_payloads = [p for t, p, _ in published if t == cross]
    cross_idents = {p["identity_uuid"] for p in cross_payloads}
    assert {"i-1", "i-2", "i-3"}.issubset(cross_idents)


# ─── Pure clusterer + projection ────────────────────────────────────────────


def test_cluster_identities_singletons():
    a = IdentityFeatures(identity_uuid="a")
    b = IdentityFeatures(identity_uuid="b")
    labels = cluster_identities([a, b])
    assert labels["a"] != labels["b"]


def test_cluster_identities_phase_handoff_unions():
    a = IdentityFeatures(
        identity_uuid="a",
        last_phase_per_decky={"d1": "command_and_control"},
        last_seen_per_decky={"d1": 1000.0},
    )
    b = IdentityFeatures(
        identity_uuid="b",
        first_phase_per_decky={"d1": "discovery"},
        first_seen_per_decky={"d1": 1100.0},
    )
    labels = cluster_identities([a, b])
    assert labels["a"] == labels["b"]


def test_from_identity_row_parses_json_lists():
    feat = from_identity_row({
        "uuid": "i-1",
        "payload_simhashes": json.dumps(["h1", "h2"]),
        "c2_endpoints": json.dumps(["c1"]),
    })
    assert feat.identity_uuid == "i-1"
    assert feat.payload_hashes == frozenset({"h1", "h2"})
    assert feat.c2_endpoints == frozenset({"c1"})


def test_from_identity_row_handles_null_and_garbage():
    f = from_identity_row({
        "uuid": "i-1",
        "payload_simhashes": None,
        "c2_endpoints": "not-json",
    })
    assert f.payload_hashes == frozenset()
    assert f.c2_endpoints == frozenset()


# ─── End-to-end tick against SQLite ────────────────────────────────────────


async def _create_identity(repo, uuid: str, **kwargs) -> str:
    now = datetime.now(timezone.utc)
    return await repo.create_attacker_identity({
        "uuid": uuid,
        "first_seen_at": now,
        "last_seen_at": now,
        "payload_simhashes": kwargs.get("payload_simhashes"),
        "c2_endpoints": kwargs.get("c2_endpoints"),
    })


@pytest.mark.anyio
async def test_tick_empty_db_returns_empty_result(repo):
    c = ConnectedComponentsCampaignClusterer()
    result = await c.tick(repo)
    assert result.campaigns_formed == []
    assert result.identities_assigned == []
    assert result.campaigns_merged == []
    assert result.campaigns_unmerged == []


@pytest.mark.anyio
async def test_tick_forms_campaign_for_shared_infra_co_op(repo):
    """Two identities with shared payload + C2 fold to one campaign.

    The canonical F5-style co-op pattern, exercised end-to-end through
    the production-row adapter. ``from_identity_row`` reads
    ``payload_simhashes`` + ``c2_endpoints`` from the AttackerIdentity
    JSON columns, builds IdentityFeatures, and the campaign weight
    crosses threshold on shared_infra alone.
    """
    await _create_identity(
        repo, "i1",
        payload_simhashes=json.dumps(["h1"]),
        c2_endpoints=json.dumps(["c1"]),
    )
    await _create_identity(
        repo, "i2",
        payload_simhashes=json.dumps(["h1"]),
        c2_endpoints=json.dumps(["c1"]),
    )

    c = ConnectedComponentsCampaignClusterer()
    result = await c.tick(repo)

    assert len(result.campaigns_formed) == 1
    formed_idents = set(result.campaigns_formed[0]["identity_uuids"])
    assert formed_idents == {"i1", "i2"}


@pytest.mark.anyio
async def test_tick_keeps_distinct_payloads_separate(repo):
    """No payload/C2 overlap → singleton per identity."""
    await _create_identity(
        repo, "i1",
        payload_simhashes=json.dumps(["h1"]),
        c2_endpoints=json.dumps(["c1"]),
    )
    await _create_identity(
        repo, "i2",
        payload_simhashes=json.dumps(["h2"]),
        c2_endpoints=json.dumps(["c2"]),
    )

    c = ConnectedComponentsCampaignClusterer()
    result = await c.tick(repo)

    assert len(result.campaigns_formed) == 2


@pytest.mark.anyio
async def test_tick_idempotent_links_existing_identity(repo):
    """Second tick on same input doesn't double-create campaigns."""
    await _create_identity(repo, "i1")
    c = ConnectedComponentsCampaignClusterer()

    r1 = await c.tick(repo)
    assert len(r1.campaigns_formed) == 1
    campaign_uuid = r1.campaigns_formed[0]["campaign_uuid"]

    r2 = await c.tick(repo)
    # Identity already linked — no new campaign, no new assignment.
    assert r2.campaigns_formed == []
    assert r2.identities_assigned == []
    # And the existing assignment persisted.
    assert await repo.count_identities_for_campaign(campaign_uuid) == 1


@pytest.mark.anyio
async def test_tick_skips_merged_out_identities(repo):
    """Merged-out identity rows must not show up as cluster inputs."""
    await _create_identity(repo, "i1")
    await _create_identity(repo, "i2")
    # Soft-merge i2 into i1 at the identity layer.
    await repo.update_identity_merged_into("i2", "i1")

    c = ConnectedComponentsCampaignClusterer()
    result = await c.tick(repo)

    # Only i1 is an active row; one campaign formed, with one identity.
    assert len(result.campaigns_formed) == 1
    assert result.campaigns_formed[0]["identity_uuids"] == ["i1"]


# ─── Factory + CLI gating ────────────────────────────────────────────────────


def test_factory_default():
    c = get_campaign_clusterer()
    assert isinstance(c, ConnectedComponentsCampaignClusterer)


def test_factory_unknown_raises(monkeypatch):
    monkeypatch.setenv("DECNET_CAMPAIGN_CLUSTERER_TYPE", "nope")
    with pytest.raises(ValueError):
        get_campaign_clusterer()


def test_campaign_clusterer_registered_in_cli():
    from decnet.cli.gating import MASTER_ONLY_COMMANDS
    assert "campaign-clusterer" in MASTER_ONLY_COMMANDS


def test_campaign_topic_builder_round_trips():
    assert _topics.campaign(_topics.CAMPAIGN_FORMED) == "campaign.formed"
    assert _topics.campaign(_topics.CAMPAIGN_IDENTITY_ASSIGNED) == (
        "campaign.identity.assigned"
    )
    assert _topics.identity(_topics.IDENTITY_CAMPAIGN_ASSIGNED) == (
        "identity.campaign.assigned"
    )
