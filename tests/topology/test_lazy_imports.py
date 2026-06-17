# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guard: importing the topology package must not eagerly pull the generator
(which drags the full SQLModel ORM, ~38MB, into every worker via the CLI).

See development/RELEASE-1.1.md (C2).
"""
import subprocess
import sys


def _import_and_report(stmt: str) -> set[str]:
    """Run `stmt` in a fresh interpreter, return the set of decnet.* modules loaded."""
    code = (
        f"import sys\n{stmt}\n"
        "print('\\n'.join(m for m in sys.modules if m.startswith('decnet')))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    return set(out.stdout.split())


def test_topology_import_does_not_pull_generator():
    loaded = _import_and_report("import decnet.topology")
    assert "decnet.topology.generator" not in loaded, (
        "topology/__init__ regressed to eager generator import — this pulls the "
        "repository → SQLModel ORM into every DB-less worker"
    )


def test_generate_still_resolvable_lazily():
    loaded = _import_and_report("from decnet.topology import generate")
    assert "decnet.topology.generator" in loaded  # accessing it loads it
    # and it's actually callable
    from decnet.topology import generate

    assert callable(generate)
