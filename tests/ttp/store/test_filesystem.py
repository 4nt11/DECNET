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
without inotify). Most behavioral assertions xfail-gated behind
E.3.5; the constants and immutability properties are GREEN today.
"""
from __future__ import annotations

import re
import sys

import pytest

from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleState
from decnet.ttp.store.impl import filesystem as fs

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="FilesystemRuleStore is Linux-only (inotify dep)",
)


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
        emits=(("T1110", None),),
        evidence_fields=(),
        state=RuleState(),
    )
    with pytest.raises(AttributeError):
        rule.rule_id = "tampered"  # type: ignore[misc]  # deliberate mutation attempt


# ── Inotify save-style coverage (xfail until E.3.5) ─────────────────


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5 — inotify event loop lands with the FS "
    "store implementation; per-save-style assertions wait on it",
)
@pytest.mark.parametrize("save_style", ["close_write", "moved_to", "create", "delete"])
async def test_each_save_style_yields_exactly_one_event(
    save_style: str,
) -> None:
    """Each of the four save styles produces exactly one
    :class:`RuleChange` event from :meth:`subscribe_changes`. xfail
    until the inotify event loop lands at E.3.5."""
    pytest.fail(f"inotify event loop not yet implemented ({save_style})")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5 — scratch-file filter wired into the "
    "event handler lands with the FS store implementation",
)
async def test_close_write_on_filtered_name_emits_no_log_line() -> None:
    """A CLOSE_WRITE event on a name failing the allowlist (e.g.
    ``.foo.yaml.swp``) produces NEITHER a parse attempt NOR a log
    line. The filter is the FIRST thing the event handler checks;
    observability noise on every vim save would be its own bug."""
    pytest.fail("event handler filter ordering not yet implemented")


# ── Atomic-swap concurrency (xfail until E.3.5) ─────────────────────


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.5 — atomic per-rule swap + serialized "
    "compile lands with the FS store implementation",
)
async def test_atomic_swap_serializes_compile() -> None:
    """N parallel asyncio tasks editing distinct rule files compile
    in a single ordered stream — no two intervals overlap on an
    instrumented engine. Concurrent :meth:`RuleEngine.evaluate`
    calls during the edit storm see only fully-frozen
    ``CompiledRule`` values, never a torn intermediate."""
    pytest.fail("atomic-swap concurrency not yet implemented")
