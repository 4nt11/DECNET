# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared runtime filesystem path resolution.

DECNET writes runtime state under a system dir provisioned by ``decnet
init`` / systemd (``/var/lib/decnet`` for state, ``/run/decnet`` for
sockets). On dev boxes without systemd, or in CI, that dir may be absent
or read-only, so callers fall back to a per-user location.

:func:`resolve_runtime_path` centralises the writable-dir probe that the
vectorstore and bus backends previously copy-pasted verbatim.
"""
from __future__ import annotations

import os


def resolve_runtime_path(
    filename: str,
    *,
    env_var: str,
    runtime_dir: str,
    user_fallback: str,
) -> str:
    """Resolve a runtime file path. Creates nothing.

    Precedence:
      1. ``$env_var`` if set (used verbatim).
      2. ``runtime_dir/filename`` if ``runtime_dir`` exists and is writable.
      3. ``user_fallback`` (``~`` expanded).

    ``runtime_dir`` is *probed*, never created: it is meant to be
    provisioned with the right ownership and perms by init/systemd, so
    creating it here with whatever perms the current process happens to
    have would be worse than falling back to the user path.
    """
    explicit = os.environ.get(env_var)
    if explicit:
        return explicit
    if os.path.isdir(runtime_dir) and os.access(runtime_dir, os.W_OK):
        return os.path.join(runtime_dir, filename)
    return os.path.expanduser(user_fallback)
