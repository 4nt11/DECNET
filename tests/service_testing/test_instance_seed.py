# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Tests for decnet/templates/instance_seed.py — the per-instance stealth
seeding helper. These tests pin NODE_NAME to assert determinism of the
seeded functions, and sweep NODE_NAMEs to assert cross-fleet divergence.
"""

import asyncio
import importlib.util
import sys
import time
from unittest.mock import patch


def _load_seed(node_name: str):
    sys.modules.pop("instance_seed", None)
    spec = importlib.util.spec_from_file_location(
        "instance_seed", "decnet/templates/instance_seed.py"
    )
    mod = importlib.util.module_from_spec(spec)
    with patch.dict("os.environ", {"NODE_NAME": node_name}, clear=False):
        spec.loader.exec_module(mod)
    return mod


def test_same_nodename_yields_stable_uuid():
    a = _load_seed("deckie-42").instance_uuid("x")
    b = _load_seed("deckie-42").instance_uuid("x")
    assert a == b


def test_different_nodename_yields_different_uuid():
    a = _load_seed("deckie-alpha").instance_uuid("x")
    b = _load_seed("deckie-beta").instance_uuid("x")
    assert a != b


def test_pick_is_deterministic_per_instance():
    choices = ["a", "b", "c", "d", "e"]
    m1 = _load_seed("hostX")
    m2 = _load_seed("hostX")
    assert m1.pick(choices) == m2.pick(choices)


def test_pick_varies_across_fleet():
    """For a reasonable fleet size, pick should land on at least 2 distinct
    values. Anything less means the seed isn't actually diversifying output."""
    choices = list("abcdefghij")
    picks = {_load_seed(f"host{i}").pick(choices) for i in range(20)}
    assert len(picks) >= 3


def test_uptime_monotonic_across_calls():
    mod = _load_seed("uptime-host")
    u1 = mod.uptime_seconds()
    time.sleep(0.02)
    u2 = mod.uptime_seconds()
    assert u2 >= u1


def test_uptime_includes_boot_offset():
    """uptime should be > a few minutes even at process start — deckies
    should not look like they just booted."""
    mod = _load_seed("fresh-host")
    assert mod.uptime_seconds() > 600


def test_fresh_bytes_is_not_deterministic():
    """fresh_bytes is per-connection randomness, not seeded — otherwise
    two MySQL handshakes to the same decky would present identical salts."""
    mod = _load_seed("host")
    assert mod.fresh_bytes(16) != mod.fresh_bytes(16)


def test_random_bytes_is_deterministic():
    """random_bytes is the *seeded* variant — used for stable per-instance
    identifiers like cluster UUIDs."""
    a = _load_seed("h").random_bytes(16, "ns")
    b = _load_seed("h").random_bytes(16, "ns")
    assert a == b


def test_jitter_sleeps_in_range():
    mod = _load_seed("jh")

    async def run():
        start = time.perf_counter()
        await mod.jitter(10, 30)
        return time.perf_counter() - start

    elapsed = asyncio.run(run())
    assert 0.005 <= elapsed <= 0.200  # generous upper bound for CI jitter
