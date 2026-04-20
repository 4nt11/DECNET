"""Allocator unit + integration tests."""
from __future__ import annotations

import pytest

from decnet.topology.allocator import (
    AllocatorExhausted,
    IPAllocator,
    SubnetAllocator,
    reserved_subnets,
)
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist, transition_status
from decnet.topology.status import TopologyStatus
from decnet.web.db.factory import get_repository


# --------------------------------------------------------------------- IPAllocator


def test_ip_allocator_sequential_skips_gateway():
    a = IPAllocator("10.0.0.0/29")  # hosts: .1 .. .6; .1 is gateway
    got = [a.next_free() for _ in range(5)]
    assert got == ["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"]


def test_ip_allocator_reserve_release_roundtrip():
    a = IPAllocator("10.0.0.0/29")
    a.reserve("10.0.0.3")
    assert not a.is_free("10.0.0.3")
    a.release("10.0.0.3")
    assert a.is_free("10.0.0.3")


def test_ip_allocator_reserve_rejects_gateway():
    a = IPAllocator("10.0.0.0/29")
    with pytest.raises(ValueError):
        a.reserve("10.0.0.1")


def test_ip_allocator_reserve_rejects_out_of_subnet():
    a = IPAllocator("10.0.0.0/29")
    with pytest.raises(ValueError):
        a.reserve("10.0.0.100")


def test_ip_allocator_next_free_after_reserve_skips():
    a = IPAllocator("10.0.0.0/29")
    a.reserve("10.0.0.2")
    assert a.next_free() == "10.0.0.3"


def test_ip_allocator_exhaustion_raises():
    a = IPAllocator("10.0.0.0/30")  # hosts: .1 .. .2; .1 gateway → only .2 usable
    assert a.next_free() == "10.0.0.2"
    with pytest.raises(AllocatorExhausted):
        a.next_free()


# --------------------------------------------------------------------- SubnetAllocator


def test_subnet_allocator_sequential():
    s = SubnetAllocator("172.20")
    assert s.next_free() == "172.20.0.0/24"
    assert s.next_free() == "172.20.1.0/24"
    assert s.next_free() == "172.20.2.0/24"


def test_subnet_allocator_skips_reserved():
    s = SubnetAllocator("172.20", reserved={"172.20.0.0/24", "172.20.1.0/24"})
    assert s.next_free() == "172.20.2.0/24"


def test_subnet_allocator_reserve_is_idempotent():
    s = SubnetAllocator("172.20")
    s.reserve("172.20.0.0/24")
    assert s.next_free() == "172.20.1.0/24"


def test_subnet_allocator_exhaustion_raises():
    reserved = {f"10.0.{i}.0/24" for i in range(256)}
    s = SubnetAllocator("10.0", reserved=reserved)
    with pytest.raises(AllocatorExhausted):
        s.next_free()


# --------------------------------------------------------------------- reserved_subnets


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="alloc",
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        cross_edge_probability=0.0,
        randomize_services=False,
        services_explicit=["ssh"],
        seed=3,
    )
    base.update(kw)
    return TopologyConfig(**base)


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "alloc.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_reserved_subnets_includes_pending_and_active(repo):
    plan_a = generate(_cfg(name="a"))
    tid_a = await persist(repo, plan_a)  # pending

    plan_b = generate(_cfg(name="b", subnet_base_prefix="172.21"))
    tid_b = await persist(repo, plan_b)
    await transition_status(repo, tid_b, TopologyStatus.DEPLOYING)
    # DEPLOYING → ACTIVE
    await transition_status(repo, tid_b, TopologyStatus.ACTIVE)

    claimed = await reserved_subnets(repo)
    for lan in plan_a.lans:
        assert lan.subnet in claimed
    for lan in plan_b.lans:
        assert lan.subnet in claimed


@pytest.mark.anyio
async def test_reserved_subnets_excludes_torn_down(repo):
    plan = generate(_cfg(name="gone"))
    tid = await persist(repo, plan)
    # pending → torn_down is legal
    await transition_status(repo, tid, TopologyStatus.TORN_DOWN)

    claimed = await reserved_subnets(repo)
    for lan in plan.lans:
        assert lan.subnet not in claimed


@pytest.mark.anyio
async def test_generate_respects_reserved(repo):
    plan_a = generate(_cfg(name="a"))
    await persist(repo, plan_a)
    claimed = await reserved_subnets(repo)
    # Second topology on the same base, told about reservations: must
    # pick subnets not in the first one's set.
    plan_b = generate(_cfg(name="b"), reserved_subnets=claimed)
    b_subnets = {lan.subnet for lan in plan_b.lans}
    a_subnets = {lan.subnet for lan in plan_a.lans}
    assert b_subnets.isdisjoint(a_subnets)
