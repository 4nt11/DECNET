# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prefork supervisor — import the base floor ONCE in a master, then fork one
child process per worker. Children share the ~70 MB import floor via
copy-on-write.

Measured on CPython 3.14 (development/cow_probe.py): an idle forked child keeps
~71 MB shared and dirties only ~1 MB private; a working child dirties ~26 MB
(its own heap, not the floor). PEP 683 immortal objects keep module/code pages
clean, so the classic refcount-dirties-CoW problem does not bite and gc.freeze()
is unnecessary on 3.14.

Contrast with :mod:`decnet.supervisor` (asyncio tasks in ONE process, shared
GIL): use that for cheap co-resident IO workers. Use prefork for workers that
must keep their OWN process / GIL — CPU-heavy or isolation-critical — but
shouldn't each re-import the world.

Each worker spec is a zero-arg callable that BLOCKS running the worker (e.g.
``lambda: asyncio.run(profiler_worker(repo))``). It executes in the forked
child; the master only forks, reaps, and restarts.
"""
from __future__ import annotations

import logging
import os
import signal
import time
from collections.abc import Callable

log = logging.getLogger("decnet.prefork")

WorkerEntry = Callable[[], None]


def run_fleet(
    specs: dict[str, WorkerEntry],
    *,
    max_backoff: float = 30.0,
    poll_interval: float = 0.2,
    stop_after: float | None = None,
) -> None:
    """Fork one child per worker and supervise them until SIGTERM/SIGINT.

    A dead child is re-forked after exponential backoff (in-process
    ``Restart=on-failure``). Backoff is tracked per worker and scheduled
    non-blockingly, so one worker's restart delay never stalls reaping of
    another. On shutdown, children get SIGTERM, then SIGKILL after a grace
    period.

    ``stop_after`` (seconds) is a test hook: cleanly shut the fleet down after
    that long instead of waiting for a signal.
    """
    if not specs:
        return

    children: dict[int, str] = {}        # pid -> name
    backoff: dict[str, float] = {n: 1.0 for n in specs}
    due: dict[str, float] = {}           # name -> earliest restart time
    stopping = {"flag": False}

    def _request_stop(_signum: int, _frame: object) -> None:
        stopping["flag"] = True

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    def spawn(name: str) -> None:
        pid = os.fork()
        if pid == 0:  # ---- child ----
            # Restore default signal handling so the worker's own asyncio
            # handlers (or KeyboardInterrupt) work as if launched standalone.
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            try:
                specs[name]()
            except KeyboardInterrupt:
                pass
            except BaseException:  # noqa: BLE001 — last-resort child logging
                log.exception("prefork: worker %s raised", name)
                os._exit(1)
            os._exit(0)
        children[pid] = name  # ---- parent ----
        log.info("prefork: spawned %s pid=%d", name, pid)

    log.info("prefork: master pid=%d forking %d workers: %s",
             os.getpid(), len(specs), ", ".join(specs))
    for name in specs:
        spawn(name)

    deadline = (time.monotonic() + stop_after) if stop_after is not None else None
    while not stopping["flag"]:
        if deadline is not None and time.monotonic() >= deadline:
            break
        now = time.monotonic()
        # Restart any workers whose backoff has elapsed.
        for name in [n for n, t in due.items() if now >= t]:
            del due[name]
            spawn(name)
        # Reap without blocking so concurrent crashes are all handled.
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            pid = 0
        if pid == 0:
            time.sleep(poll_interval)
            continue
        name = children.pop(pid, None)
        if name is None:
            continue
        code = os.waitstatus_to_exitcode(status)
        log.warning("prefork: %s (pid=%d) exited code=%d; restart in %.0fs",
                    name, pid, code, backoff[name])
        due[name] = time.monotonic() + backoff[name]
        backoff[name] = min(backoff[name] * 2.0, max_backoff)

    _shutdown(children)


def _shutdown(children: dict[int, str], *, grace: float = 15.0) -> None:
    """SIGTERM all children, reap within ``grace``, SIGKILL stragglers."""
    for pid in list(children):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            children.pop(pid, None)
    deadline = time.monotonic() + grace
    while children and time.monotonic() < deadline:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid:
            children.pop(pid, None)
        else:
            time.sleep(0.1)
    for pid in list(children):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    log.info("prefork: fleet shut down")
