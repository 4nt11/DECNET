"""DECNET self-updater daemon.

Runs on each worker alongside ``decnet agent``. Receives working-tree
tarballs from the master and owns the agent's lifecycle: snapshot →
install → restart → probe → auto-rollback on failure.

Deliberately separate process, separate venv, separate mTLS cert so that
a broken ``decnet agent`` push can always be rolled back by the updater
that shipped it. See ``wiki/Remote-Updates.md``.
"""
