# SPDX-License-Identifier: AGPL-3.0-or-later
"""E.2.7 — Static decoupling lint for ``decnet/ttp/``.

The "no SPOF" decoupling rule §2 of TTP_TAGGING.md: tagging code
must NEVER import an intel-provider module directly. Intel-derived
data flows through ``decnet.web.db.models`` (the ``AttackerIntel``
row), not through a function call into
``decnet.intel.{abuseipdb,greynoise,feodo,threatfox}``. A failed
provider produces an empty join, not a crash inside the tagger
worker.

The same property holds for biometrics: nothing under
``decnet/ttp/`` may reach into ``decnet.profiler.keystroke.*``.
Future biometric ingesters will land in their own subpackages with
the same DB-mediated bridge.

This is a pure AST walk — no module-level import side effects, no
runtime dependencies. The check runs on every TTP source file
(skipping ``__pycache__`` and dunder names) and surfaces a
``ImportFrom``/``Import`` violation with file path + line number on
failure.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

import decnet.ttp as _ttp_pkg


_TTP_ROOT: Path = Path(_ttp_pkg.__file__).resolve().parent

# Exact module names the tagger MUST NOT import.
_FORBIDDEN_EXACT: frozenset[str] = frozenset({
    "decnet.intel.abuseipdb",
    "decnet.intel.greynoise",
    "decnet.intel.feodo",
    "decnet.intel.threatfox",
})

# Forbidden by-prefix: anything under these subpackages is off-limits.
_FORBIDDEN_PREFIXES: tuple[str, ...] = (
    "decnet.profiler.keystroke",
)


def _is_forbidden(module_name: str) -> bool:
    if module_name in _FORBIDDEN_EXACT:
        return True
    return any(
        module_name == prefix or module_name.startswith(prefix + ".")
        for prefix in _FORBIDDEN_PREFIXES
    )


def _ttp_python_files() -> list[Path]:
    files: list[Path] = []
    for p in _TTP_ROOT.rglob("*.py"):
        # Skip caches and any future stubs/shims that might slip in.
        if "__pycache__" in p.parts:
            continue
        files.append(p)
    return files


def test_at_least_one_ttp_file_visited() -> None:
    """Sanity guard: a future refactor that moves the package or
    renames the import root must not silently neuter the lint by
    walking zero files."""
    files = _ttp_python_files()
    assert files, f"no .py files under {_TTP_ROOT} — refactor regressed the lint"
    # Spot-check that the lifters and the worker live under the root,
    # otherwise the lint scope is wrong.
    names = {p.name for p in files}
    assert "worker.py" in names
    assert "base.py" in names


@pytest.mark.parametrize("path", _ttp_python_files(), ids=lambda p: str(p.relative_to(_TTP_ROOT)))
def test_no_forbidden_imports(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_forbidden(alias.name):
                    violations.append(
                        f"{path}:{node.lineno} import {alias.name}"
                    )
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if _is_forbidden(mod):
                violations.append(
                    f"{path}:{node.lineno} from {mod} import …"
                )
    assert not violations, (
        "decoupling rule §2 violated — TTP code must reach intel "
        "data via decnet.web.db.models only:\n  "
        + "\n  ".join(violations)
    )
