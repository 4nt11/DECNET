# SPDX-License-Identifier: AGPL-3.0-or-later
"""Async deploy/mutate lifecycle runner.

The runner is invoked by the master API handlers (deploy + mutate) after
they write ``DeckyLifecycle`` rows and return 202 Accepted to the
caller.  It executes the actual docker work off the request thread,
flips lifecycle row status through ``running -> succeeded|failed``, and
emits ``decky.<name>.lifecycle`` bus signals on every transition.

Strategy classes encapsulate transport (local docker on master vs
remote agent over mTLS).  ``runner.run_deploy`` / ``run_mutate`` pick
the right strategy from the request context.
"""
from decnet.lifecycle.runner import run_deploy, run_mutate

__all__ = ["run_deploy", "run_mutate"]
