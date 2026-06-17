# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared CPU-kernel offload — run a pure, picklable function in a process pool
so GIL-bound compute doesn't block the event loop (or its co-hosted workers).

Used by ``decnet supervise cpu`` (see ``decnet/cli/supervise.py``), which hosts
several CPU-bound workers in one process and installs ONE shared
``ProcessPoolExecutor`` here. When no executor is installed — standalone workers
and every test — :func:`run_kernel` runs the kernel inline, so behaviour is
identical to before this module existed.

Contract for an offloadable kernel: a module-level function (picklable by
reference) that is pure (no DB / clock / I/O), taking and returning picklable
values. The clustering connected-components kernels satisfy this.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Callable, TypeVar

_T = TypeVar("_T")

_executor: ProcessPoolExecutor | None = None


def set_executor(ex: ProcessPoolExecutor | None) -> None:
    """Install (``ex``) or clear (``None``) the shared pool. Idempotent."""
    global _executor
    _executor = ex


def get_executor() -> ProcessPoolExecutor | None:
    return _executor


async def run_kernel(
    fn: Callable[..., _T], *args: Any, offload_if: bool = True
) -> _T:
    """Run ``fn(*args)``, offloading to the shared pool when one is installed
    and ``offload_if`` holds; otherwise run inline.

    ``offload_if`` lets the caller skip the pickle round-trip for inputs too
    small to be worth a cross-process hop — the caller knows the problem size,
    this module does not.
    # ponytail: boolean gate, not an auto-tuned threshold. If kernels start
    # varying wildly in cost, measure and move the decision here.
    """
    ex = _executor
    if ex is None or not offload_if:
        return fn(*args)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(ex, fn, *args)
