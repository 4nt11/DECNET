# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression tests for :func:`decnet.orchestrator.drivers.get_driver_for`.

BUG-1: EditAction had no registered driver — get_driver_for raised TypeError
instead of returning an SSHDriver, silently crashing every edit tick.
"""
from __future__ import annotations

import pytest

from decnet.orchestrator.drivers import get_driver_for
from decnet.orchestrator.drivers.ssh import SSHDriver
from decnet.orchestrator.scheduler import EditAction, FileAction, TrafficAction


def _traffic_action() -> TrafficAction:
    return TrafficAction(
        src_uuid="u1", src_name="decky-01",
        dst_uuid="u2", dst_name="decky-02",
        dst_ip="10.0.0.2",
    )


def _file_action() -> FileAction:
    return FileAction(
        dst_uuid="u1", dst_name="decky-01",
        path="/tmp/test.txt",
        content="hello",
    )


def _edit_action() -> EditAction:
    return EditAction(
        dst_uuid="u1", dst_name="decky-01",
        path="/tmp/notes.txt",
        persona="alice",
        content_class="note",
        previous_body="old content",
        synthetic_file_uuid="sf-uuid-001",
    )


def test_traffic_action_resolves_to_ssh_driver() -> None:
    drv = get_driver_for(_traffic_action())
    assert isinstance(drv, SSHDriver)


def test_file_action_resolves_to_ssh_driver() -> None:
    drv = get_driver_for(_file_action())
    assert isinstance(drv, SSHDriver)


def test_edit_action_resolves_to_ssh_driver() -> None:
    """BUG-1 regression: EditAction must resolve to SSHDriver, not TypeError."""
    # Before the fix this raised:
    #   TypeError: no driver registered for action type EditAction
    drv = get_driver_for(_edit_action())
    assert isinstance(drv, SSHDriver)


@pytest.mark.asyncio
async def test_edit_action_driver_executes_without_crash(monkeypatch) -> None:
    """BUG-1 regression: SSHDriver.run(EditAction) must not crash silently.

    We mock _run to avoid needing a live Docker daemon; the important
    assertion is that the driver resolves, runs, and returns an ActivityResult.
    """
    from decnet.orchestrator.drivers import ssh as ssh_driver
    from decnet.orchestrator.drivers.base import ActivityResult

    async def fake_run(argv):
        return 0, "", ""

    monkeypatch.setattr(ssh_driver, "_run", fake_run)

    drv = get_driver_for(_edit_action())
    result = await drv.run(_edit_action())
    assert isinstance(result, ActivityResult)
