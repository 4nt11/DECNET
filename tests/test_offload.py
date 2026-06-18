# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the shared CPU-kernel offload (DECNET 1.1 cpu group).

Proves the offloaded result is identical to the inline result — i.e. the kernel
and its inputs survive the process boundary and the GIL-relief path is correct,
not just fast.
"""
from __future__ import annotations

import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor

import pytest

from decnet import offload
from decnet.clustering.impl.connected_components import cluster_observations
from decnet.clustering.impl.similarity import Observation

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _clear_executor():
    offload.set_executor(None)
    yield
    offload.set_executor(None)


async def test_inline_when_no_executor():
    assert offload.get_executor() is None
    out = await offload.run_kernel(lambda a, b: a + b, 2, 3)
    assert out == 5  # closures are fine on the inline path (no pickling)


async def test_offload_if_false_runs_inline_even_with_pool():
    with ProcessPoolExecutor(
        max_workers=1, mp_context=mp.get_context("forkserver")
    ) as pool:
        offload.set_executor(pool)
        # a closure would fail to pickle — proves this stayed inline
        out = await offload.run_kernel(lambda x: x * 10, 4, offload_if=False)
        assert out == 40


async def test_offloaded_result_equals_inline():
    obs = [
        Observation(observation_id="a", ja3="x", hassh=None, asn=1),
        Observation(observation_id="b", ja3="x", hassh=None, asn=1),
        Observation(observation_id="c", ja3="y", hassh=None, asn=2),
    ]
    inline = cluster_observations(obs)

    with ProcessPoolExecutor(
        max_workers=2, mp_context=mp.get_context("forkserver")
    ) as pool:
        offload.set_executor(pool)
        offloaded = await offload.run_kernel(cluster_observations, obs)

    assert offloaded == inline  # identical across the process boundary


async def test_set_get_executor_roundtrip():
    assert offload.get_executor() is None
    with ProcessPoolExecutor(max_workers=1) as pool:
        offload.set_executor(pool)
        assert offload.get_executor() is pool
    offload.set_executor(None)
    assert offload.get_executor() is None
