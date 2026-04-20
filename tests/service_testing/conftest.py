"""
Shared helpers for binary-protocol service tests.
"""

import os
import threading
from types import ModuleType
from unittest.mock import MagicMock

import pytest
from hypothesis import HealthCheck


_FUZZ_SETTINGS = dict(
    max_examples=int(os.environ.get("HYPOTHESIS_MAX_EXAMPLES", "200")),
    deadline=2000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


def make_fake_syslog_bridge() -> ModuleType:
    mod = ModuleType("syslog_bridge")
    mod.syslog_line = MagicMock(return_value="")
    mod.write_syslog_file = MagicMock()
    mod.forward_syslog = MagicMock()
    mod.SEVERITY_WARNING = 4
    mod.SEVERITY_INFO = 6
    return mod


def run_with_timeout(fn, *args, timeout: float = 2.0) -> None:
    """Run fn(*args) in a daemon thread. pytest.fail if it doesn't return in time."""
    exc_box: list[BaseException] = []

    def _target():
        try:
            fn(*args)
        except Exception as e:
            exc_box.append(e)

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        pytest.fail(f"data_received hung for >{timeout}s — likely infinite loop")
    if exc_box:
        raise exc_box[0]
