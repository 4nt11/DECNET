# SPDX-License-Identifier: AGPL-3.0-or-later
"""Standalone driver for the prefork supervisor — runnable directly OR via
tests/test_prefork.py (which execs it in a subprocess so no fork happens inside
the pytest/xdist worker).

  python tests/prefork_driver.py <out_dir>

Forks two fake workers under decnet.prefork.run_fleet:
  * "tick"    — append a line every 0.2s forever (proves a worker runs & stays up)
  * "crasher" — write a marker then exit(1) (proves restart-on-crash)
Runs for ~2s via stop_after, then shuts the fleet down. Writes results into
<out_dir>; the caller asserts on them.
"""
from __future__ import annotations

import os
import sys
import time

# Running this file as a script puts its own dir (tests/) on sys.path[0], which
# shadows the stdlib `logging` via tests/logging/. Drop it before importing
# decnet (still importable — it's installed in the venv).
if sys.path and os.path.basename(sys.path[0]) == "tests":
    sys.path.pop(0)

from decnet.prefork import run_fleet  # noqa: E402


def main(out: str) -> None:
    tick_log = os.path.join(out, "tick.log")
    crash_log = os.path.join(out, "crash.log")

    def tick() -> None:
        while True:
            with open(tick_log, "a") as f:
                f.write("t\n")
            time.sleep(0.2)

    def crasher() -> None:
        with open(crash_log, "a") as f:
            f.write("c\n")
        time.sleep(0.15)
        os._exit(1)

    # Fast backoff so we observe multiple restarts inside the short window.
    run_fleet(
        {"tick": tick, "crasher": crasher},
        max_backoff=0.2,
        poll_interval=0.05,
        stop_after=2.0,
    )


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
