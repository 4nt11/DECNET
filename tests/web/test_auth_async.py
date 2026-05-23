# SPDX-License-Identifier: AGPL-3.0-or-later
"""
averify_password / ahash_password run bcrypt on a thread so the event
loop can serve other requests while hashing. Contract: they must produce
identical results to the sync versions.
"""
import pytest

from decnet.web.auth import (
    ahash_password,
    averify_password,
    get_password_hash,
    verify_password,
)


@pytest.mark.asyncio
async def test_ahash_matches_sync_hash_verify():
    hashed = await ahash_password("hunter2")
    assert verify_password("hunter2", hashed)
    assert not verify_password("wrong", hashed)


@pytest.mark.asyncio
async def test_averify_matches_sync_verify():
    hashed = get_password_hash("s3cret")
    assert await averify_password("s3cret", hashed) is True
    assert await averify_password("s3cre", hashed) is False


@pytest.mark.asyncio
async def test_averify_does_not_block_loop():
    """Two concurrent averify calls should run in parallel (on threads).

    With `asyncio.to_thread`, total wall time is ~max(a, b), not a+b.
    """
    import asyncio, time

    hashed = get_password_hash("x")
    t0 = time.perf_counter()
    a, b = await asyncio.gather(
        averify_password("x", hashed),
        averify_password("x", hashed),
    )
    elapsed = time.perf_counter() - t0
    assert a and b
    # Sequential would be ~2× a single verify. Parallel on threads is ~1×.
    # Single verify is ~250ms at rounds=12. Allow slack for CI noise.
    single = time.perf_counter()
    verify_password("x", hashed)
    single_time = time.perf_counter() - single
    assert elapsed < 1.7 * single_time, f"concurrent {elapsed:.3f}s vs single {single_time:.3f}s"
