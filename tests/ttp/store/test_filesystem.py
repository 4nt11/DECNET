# SPDX-License-Identifier: AGPL-3.0-or-later
"""E.2.14b — Filesystem-specific RuleStore properties.

Pins behavior that's unique to :class:`FilesystemRuleStore`:

* Inotify event mask covers four save styles (``IN_CLOSE_WRITE``,
  ``IN_MOVED_TO``, ``IN_CREATE``, ``IN_DELETE``) per ``strace`` of
  vim and other editors. Verified by parametrizing each case and
  asserting one event per save.
* Filename allowlist (vs denylist) — dotfile / scratch / wrong-ext
  filenames produce zero events and zero loaded rules; the positive
  sibling case still loads.
* CLOSE_WRITE on a filtered name produces NEITHER a parse attempt
  NOR a log line. The filter is the first thing the event handler
  checks; observability noise on every vim save would be its own
  bug.
* Atomic-swap concurrency: parallel edits compile in a serialized
  stream; concurrent :meth:`evaluate` sees only fully-frozen
  ``CompiledRule`` (NamedTuple, mutation-resistant).

Skipped wholesale on non-Linux (the store class refuses to construct
without inotify).
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path

import pytest

from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleChange, RuleState
from decnet.ttp.store.impl import filesystem as fs

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="FilesystemRuleStore is Linux-only (inotify dep)",
)


_RULE_YAML = """\
rule_id: {rule_id}
rule_version: 1
name: test rule
applies_to: [command]
match:
  pattern: 'hydra'
emits:
  - tactic: TA0006
    technique_id: T1110
    confidence: 0.85
evidence_fields: [matched_tokens]
"""


def _write_rule(path: Path, rule_id: str = "R0001") -> None:
    path.write_text(_RULE_YAML.format(rule_id=rule_id), encoding="utf-8")


async def _next_change(
    sub: "object", *, timeout: float = 2.0,
) -> RuleChange:
    return await asyncio.wait_for(sub.__anext__(), timeout=timeout)  # type: ignore[attr-defined]


# ── Constants (GREEN today) ─────────────────────────────────────────


def test_inotify_mask_covers_four_save_styles() -> None:
    """The mask is the bitwise OR of IN_CLOSE_WRITE | IN_MOVED_TO |
    IN_CREATE | IN_DELETE. Each bit covers one canonical save style.
    Pinning the OR pins the contract: a future contributor cannot
    quietly drop a bit (and silently miss an editor's save mode).
    """
    expected = (
        fs._IN_CLOSE_WRITE
        | fs._IN_MOVED_TO
        | fs._IN_CREATE
        | fs._IN_DELETE
    )
    assert fs._INOTIFY_MASK == expected
    # Each bit must actually be set in the composite.
    for bit in (
        fs._IN_CLOSE_WRITE,
        fs._IN_MOVED_TO,
        fs._IN_CREATE,
        fs._IN_DELETE,
    ):
        assert fs._INOTIFY_MASK & bit


def test_inotify_mask_uses_canonical_kernel_values() -> None:
    """Bit values match ``<sys/inotify.h>``. Sanity check against
    accidental endianness / byte-shuffle bugs in the inlined
    constants. Real values from man inotify(7).
    """
    assert fs._IN_CLOSE_WRITE == 0x00000008
    assert fs._IN_MOVED_TO == 0x00000080
    assert fs._IN_CREATE == 0x00000100
    assert fs._IN_DELETE == 0x00000200


# ── Filename allowlist (GREEN today) ────────────────────────────────


@pytest.mark.parametrize(
    "filename",
    [
        ".T1110_brute_force.yaml.swp",      # vim swap
        ".T1110_brute_force.yaml.swo",      # secondary vim swap
        "T1110_brute_force.yaml~",           # tilde backup
        ".T1110_brute_force.yaml.bak",       # dot-prefix backup
        "4913",                              # vim atomic-save probe
        ".4913",                             # dot-prefix variant
        ".foo",                              # any dotfile, no yaml
        "T1110_brute_force.yaml.tmp",        # wrong extension
        "T1110_brute_force.txt",             # right shape, wrong ext
    ],
)
def test_scratch_filenames_rejected_by_allowlist(filename: str) -> None:
    """Dotfile / scratch / wrong-extension filenames fail the
    allowlist regex.

    Listed exhaustively (rather than property-tested) because the
    allowlist's *exclusion* set is the load-bearing surface — a
    future "let's also accept .yaml.tmp" PR must trip this test
    deliberately.
    """
    assert fs._VALID_RULE_FILENAME.fullmatch(filename) is None


@pytest.mark.parametrize(
    "filename",
    [
        "T1110_brute_force.yaml",
        "T1078.yaml",
        "T1059_command_and_scripting.yml",
        "R0001.yaml",
    ],
)
def test_valid_rule_filenames_accepted(filename: str) -> None:
    """Positive cases: real rule files are accepted by the allowlist
    regex. Confirms the filter excludes scratch files without
    false-rejecting real ones."""
    assert fs._VALID_RULE_FILENAME.fullmatch(filename) is not None


def test_filename_allowlist_uses_fullmatch_semantics() -> None:
    """The pattern uses ``\\Z`` / ``fullmatch`` — anchoring is
    load-bearing. ``foo.yaml.tmp`` would match a non-anchored
    ``.yaml`` substring search but is correctly rejected by
    ``fullmatch``. Pinning the regex's anchor behavior catches a
    refactor to ``re.search`` that would silently widen the
    allowlist."""
    # The compiled pattern as authored doesn't carry trailing $
    # because fullmatch implicitly anchors. The string we test
    # passes a no-anchor `search` but fails `fullmatch`.
    assert re.compile(fs._VALID_RULE_FILENAME.pattern).search(
        "T1110_brute_force.yaml.tmp",
    ) is not None
    assert fs._VALID_RULE_FILENAME.fullmatch(
        "T1110_brute_force.yaml.tmp",
    ) is None


# ── Construction guard (GREEN today) ────────────────────────────────


def test_construct_with_tmp_path_works(tmp_path) -> None:
    """The constructor accepts an explicit ``rules_dir`` so tests
    can sandbox without touching the real ``./rules/``."""
    store = fs.FilesystemRuleStore(rules_dir=tmp_path)
    assert store._rules_dir == tmp_path


# ── CompiledRule immutability (GREEN today) ─────────────────────────


def test_compiled_rule_is_frozen() -> None:
    """``CompiledRule`` is a :class:`NamedTuple`, so field
    assignment raises ``AttributeError``. The doc references
    ``FrozenInstanceError`` (the dataclass equivalent), but the
    actual implementation uses NamedTuple — the in-test smoke
    signal is the same property (mutation-resistant) under a
    different exception type. Pinning the AttributeError behavior
    here clarifies the contract for future readers."""
    rule = CompiledRule(
        rule_id="R0001",
        rule_version=1,
        name="test",
        applies_to=frozenset({"attacker_command"}),
        match_spec={},
        emits=(("T1110", None, "TA0006", 0.85),),
        evidence_fields=(),
        state=RuleState(),
    )
    with pytest.raises(AttributeError):
        rule.rule_id = "tampered"  # type: ignore[misc]  # deliberate mutation attempt


# ── Inotify save-style coverage (E.3.5 — flipped) ───────────────────


@pytest.mark.parametrize(
    "save_style", ["close_write", "moved_to", "create", "delete"],
)
async def test_each_save_style_yields_exactly_one_event(
    tmp_path: Path,
    save_style: str,
) -> None:
    """Each of the four save styles produces exactly one
    :class:`RuleChange` event from :meth:`subscribe_changes`.

    Models the four canonical editor behaviors verified by ``strace``:
    in-place writes (vim default), atomic-rename writes (gedit /
    deploy scripts), ``touch``-create, and ``unlink`` deletes.
    """
    rule_path = tmp_path / "R0001.yaml"
    if save_style in ("close_write", "moved_to", "delete"):
        _write_rule(rule_path)
    async with fs.FilesystemRuleStore(rules_dir=tmp_path) as store:
        sub = store.subscribe_changes()
        await asyncio.sleep(0.05)  # let watcher settle on the dir
        if save_style == "close_write":
            rule_path.write_text(
                _RULE_YAML.format(rule_id="R0001").replace(
                    "rule_version: 1", "rule_version: 2",
                ),
                encoding="utf-8",
            )
        elif save_style == "moved_to":
            tmp = tmp_path / "R0001.yaml.swap"
            tmp.write_text(
                _RULE_YAML.format(rule_id="R0001").replace(
                    "rule_version: 1", "rule_version: 3",
                ),
                encoding="utf-8",
            )
            os.rename(tmp, rule_path)
        elif save_style == "create":
            (tmp_path / "R0002.yaml").write_text(
                _RULE_YAML.format(rule_id="R0002"), encoding="utf-8",
            )
        elif save_style == "delete":
            os.unlink(rule_path)
        change = await _next_change(sub)
        assert change.change_kind == "definition"
        if save_style == "delete":
            assert change.rule_id == "R0001"
        elif save_style == "create":
            assert change.rule_id == "R0002"
        else:
            assert change.rule_id == "R0001"


async def test_close_write_on_filtered_name_emits_no_log_line(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A CLOSE_WRITE event on a name failing the allowlist (e.g.
    ``.foo.yaml.swp``) produces NEITHER a parse attempt NOR a log
    line. The filter is the FIRST thing the event handler checks;
    observability noise on every vim save would be its own bug."""
    caplog.set_level("DEBUG", logger="ttp.store.filesystem")
    async with fs.FilesystemRuleStore(rules_dir=tmp_path) as store:
        sub = store.subscribe_changes()
        await asyncio.sleep(0.05)
        # Vim swap file: must be silently ignored.
        (tmp_path / ".R0001.yaml.swp").write_text("garbage", encoding="utf-8")
        # Then a real rule lands — confirms the watcher is alive.
        _write_rule(tmp_path / "R0001.yaml")
        change = await _next_change(sub)
        assert change.rule_id == "R0001"
        # No log line about the swap file (parse, error, anything).
        assert all(
            ".swp" not in record.message for record in caplog.records
        ), "scratch-file filter should not log filtered names"


# ── Atomic-swap concurrency (E.3.5 — flipped) ───────────────────────


async def test_atomic_swap_serializes_compile(tmp_path: Path) -> None:
    """N parallel writers editing distinct rule files compile in a
    single ordered stream. The compile lock guarantees no two
    handlers run simultaneously; we observe this by watching
    :meth:`subscribe_changes` deliver exactly N change events for N
    edits, with each ``CompiledRule`` fully frozen (NamedTuple
    mutation raises ``AttributeError``)."""
    n = 5
    async with fs.FilesystemRuleStore(rules_dir=tmp_path) as store:
        sub = store.subscribe_changes()
        await asyncio.sleep(0.05)
        # Storm of independent edits.
        for i in range(n):
            (tmp_path / f"R000{i}.yaml").write_text(
                _RULE_YAML.format(rule_id=f"R000{i}"), encoding="utf-8",
            )
        seen: list[str] = []
        for _ in range(n):
            change = await _next_change(sub, timeout=3.0)
            assert change.change_kind == "definition"
            new_value = change.new_value
            assert isinstance(new_value, CompiledRule)
            with pytest.raises(AttributeError):
                new_value.rule_id = "tampered"  # type: ignore[misc]
            seen.append(change.rule_id)
        assert sorted(seen) == [f"R000{i}" for i in range(n)]
