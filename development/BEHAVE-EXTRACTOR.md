# BEHAVE-SHELL Extraction Engine — Implementation Route

**Status:** pre-implementation. Sibling to `BEHAVE-INTEGRATION.md`.
**Scope:** the inside of `decnet/profiler/behave_shell/`. Nothing else.
**Acceptance gate:** the five-class calibration grid in
`BEHAVE-INTEGRATION.md` §"Calibration grid IS the regression test."

This doc is the **construction manual** for the engine. The
integration doc says *what* the engine plugs into; this doc says
*how to build it from zero to v0 in a deterministic sequence*.

---

## Mission

Take an asciinema-style PTY event stream for one session, return an
`Iterable[Observation]` of BEHAVE-SHELL primitives. Pure library:
no I/O, no bus, no DB. Worker owns those.

```python
def extract_session(
    events:  Iterable[AsciinemaEvent],   # [t_float, kind: 'i'|'o', data: str]
    *,
    sid:     str,
    source:  str = "decnet/profiler/behave_shell/extract.py",
) -> Iterable[Observation]:
```

`AsciinemaEvent` is a 3-tuple `(t, kind, data)` matching the on-disk
shard line format. No fancy class — a tuple is honest about what it is.

## Single-pass discipline

A naïve engine re-walks the event stream once per primitive, paying
O(n × primitives) for nothing. We don't do that.

Single pass over events builds a `SessionContext` — a precomputed
bundle of indexes that every feature module reads from. Cheap; one
walk; reproducible.

```python
@dataclass(frozen=True, slots=True)
class SessionContext:
    sid:               str
    source:            str
    evidence_ref:      str
    t_start:           float
    t_end:             float
    duration_s:        float

    # Raw event slices (already filtered by kind)
    input_events:      tuple[InputEvent, ...]    # ('i', t, data)
    output_events:     tuple[OutputEvent, ...]   # ('o', t, data)

    # Derived once, used everywhere
    iats:              tuple[float, ...]         # IATs between input events
    paste_bursts:      tuple[PasteBurst, ...]    # detected paste regions
    commands:          tuple[Command, ...]       # split on \r / \n
    inter_cmd_iats:    tuple[float, ...]         # IATs between command boundaries
    output_per_cmd:    tuple[int, ...]           # output bytes between cmd_i and cmd_{i+1}
```

All feature modules take `ctx: SessionContext` and yield 0 or more
Observations. Single source of truth, single parse cost.

## Engine layout

```
decnet/profiler/behave_shell/
├── __init__.py            re-exports extract_session
├── extract.py             extract_session() + SessionContext build
├── _parse.py              asciinema event types + parsing helpers
├── _ctx.py                SessionContext dataclass + builders
├── _thresholds.py         all numeric thresholds, one place, named constants
└── _features/
    ├── __init__.py        FEATURES tuple — registered list of feature funcs
    ├── motor.py
    ├── cognitive.py
    └── temporal.py        (later)
```

`extract.py` is short:

```python
def extract_session(events, *, sid, source="..."):
    ctx = build_session_context(events, sid=sid, source=source)
    for feature_fn in FEATURES:
        yield from feature_fn(ctx)
```

That's the whole orchestration. Adding a primitive = adding a function
to `_features/<family>.py` and registering it in `FEATURES`.

## Threshold table convention

Every numeric threshold lives in `_thresholds.py` as a named constant
with a docstring citing the registry's `notes:` field. **Never inline
magic numbers in feature code.** When calibration drifts, you change
one file.

```python
# decnet/profiler/behave_shell/_thresholds.py
"""Numeric thresholds for BEHAVE-SHELL primitive classification.

Each constant cites its calibration source. When the registry's
`notes:` field disagrees with a constant here, the registry is
authoritative — fix the constant, re-run the grid.
"""

# motor.paste_burst_rate buckets — events per minute of session
PASTE_RATE_OCCASIONAL_MIN = 0.5   # at least one paste every two minutes
PASTE_RATE_HABITUAL_MIN   = 3.0   # paste-driven workflow

# cognitive.inter_command_latency_class — seconds (median IAT between commands)
ICL_TYPING_SPEED_MAX      = 2.0
ICL_DELIBERATE_MAX        = 8.0
ICL_LLM_LIGHTWEIGHT_MAX   = 8.0   # 2-8s band; lower bound = ICL_TYPING_SPEED_MAX
ICL_LLM_HEAVYWEIGHT_MAX   = 30.0  # 8-30s band — registry primitives.py:140-149
# > 30s = "long"
```

## Full registry scope — what the engine owns, what it doesn't

Before the route: a sober count. The BEHAVE-SHELL registry today
contains roughly **53 primitives** across 8 top-level domains. Not
all of them are extractable from a single PTY session; some need
observation history; some belong to a different sensor entirely.

Three tiers:

### Tier A — Per-session shell-extractable (37 primitives)

Computable from one `(decky, service, sid)` shard. The extractor
owns these end-to-end.

| Domain | Primitive | Source signal |
|---|---|---|
| motor | `motor.input_modality` | paste-burst detector |
| motor | `motor.paste_burst_rate` | paste-burst counter |
| motor | `motor.keystroke_cadence` | IAT histogram shape |
| motor | `motor.motor_stability` | IAT outlier rate |
| motor | `motor.error_correction` | backspace-relative-to-error timing |
| motor | `motor.command_chunking` | intra-command IAT variance |
| motor | `motor.shell_mastery.tab_completion` | `\t` rate per command |
| motor | `motor.shell_mastery.shortcut_usage` | ^A/^E/^W/^U/^R/^B/^F rate |
| motor | `motor.shell_mastery.pipe_chaining_depth` | `\|` count per command |
| cognitive | `cognitive.inter_command_latency_class` | median inter-command IAT bucketed |
| cognitive | `cognitive.inter_command_consistency` | CV of inter-command IATs |
| cognitive | `cognitive.command_branch_diversity` | unique-first-token / total-commands |
| cognitive | `cognitive.feedback_loop_engagement` | Pearson r(output_bytes, next_pause) |
| cognitive | `cognitive.cognitive_load` | composite (IAT entropy + error rate + chunking) |
| cognitive | `cognitive.exploration_style` | command-graph branching shape |
| cognitive | `cognitive.planning_depth` | think-pause-length distribution |
| cognitive | `cognitive.tool_vocabulary` | distinct first-tokens normalised |
| cognitive | `cognitive.error_resilience.retry_tactic` | post-error command relation |
| cognitive | `cognitive.error_resilience.frustration_typing` | error-vs-success keystroke speed delta |
| cognitive | `cognitive.error_resilience.fallback_to_man` | `man`/`--help` invocation post-error |
| temporal | `temporal.session_duration` | `duration_s` bucketed |
| temporal | `temporal.escalation_pattern` | command-rate over rolling windows |
| temporal | `temporal.lifecycle_markers.landing_ritual` | first-N-commands signature |
| temporal | `temporal.lifecycle_markers.exit_behavior` | last-command + exit-code analysis |
| operational | `operational.objective` | command-intent classifier (recon / exfil / persistence / lateral / destructive) |
| operational | `operational.opsec_discipline` | history-clearing, log-tampering, .bash_history rm |
| operational | `operational.cleanup_behavior` | exit-time cleanup commands |
| operational | `operational.multi_actor_indicators` | mid-session pace/style shift detection |
| environmental | `environmental.shell_type` | prompt-string sniff from `'o'` events |
| environmental | `environmental.terminal_multiplexer` | tmux/screen escape sequences |
| environmental | `environmental.keyboard_layout` | bigram-frequency layout fingerprint |
| environmental | `environmental.locale` | `LANG`/`LC_*` envvar dump if `env` runs; output language sniff |
| environmental | `environmental.numpad_usage` | numeric input arrival pattern (weak) |
| emotional_valence | `emotional_valence.valence` | obscenity / praise / neutral lexicon |
| emotional_valence | `emotional_valence.arousal` | typing-speed delta + capslock + repeated bangs |
| emotional_valence | `emotional_valence.stress_response` | post-error speed-up vs slow-down |
| emotional_valence | `emotional_valence.frustration_venting` | `fuck`/`shit`/etc. detection (registry value is binary) |

The emotional_valence primitives are SOFT and will produce false
positives. Documented as such; emit at confidence ≤ 0.5 per the
confidence convention.

### Tier B — Cross-session (computed by attribution engine, not extractor)

8 primitives that **cannot honestly be computed from one session**.
The extractor does not emit these. The attribution engine
(`ATTRIBUTION-ENGINE.md`) computes them during aggregation, reading
the per-attacker observation history. Cross-reference: a TODO in
`ATTRIBUTION-ENGINE.md` notes that aggregation may include
*derivation*, not just *merging*.

| Domain | Primitive | Why cross-session |
|---|---|---|
| temporal | `temporal.session_timing` | diurnal/nocturnal/irregular requires multiple sessions |
| temporal | `temporal.persistence` | hit_and_run/return_visitor/resident is intrinsically multi-session |
| temporal | `temporal.lifecycle_markers.idle_periodicity` | periodicity needs a long enough sample |
| cultural | `cultural.meal_break_gaps` | gap pattern over days |
| cultural | `cultural.periodic_micro_pauses` | needs many sessions to find regular intervals |
| cultural | `cultural.dst_behavior` | needs sessions spanning a DST transition |
| cultural | `cultural.weekend_cadence` | needs a week+ of sessions |
| cultural | `cultural.holiday_gaps` | needs ≥ a year for honest claim |

If you find yourself implementing one of these in the extractor,
**stop**. It's an attribution-engine concern.

### Tier C — Network domain (out of scope for this engine entirely)

The full `toolchain.*` subtree —
TLS / transport / SSH / HTTP / C2 / protocol_abuse / payload
fingerprints. Roughly 25 primitives. These come from the sniffer /
prober / correlation pipeline, not from PTY session extraction.

Two paths to populate them, both NOT this doc:

1. **Wrap existing DECNET workers** (sniffer, prober, correlation,
   intel) to emit `attacker.observation.toolchain.*` from their
   existing outputs. Pragmatic, ships sooner. Filed as a future
   "wire existing producers to BEHAVE" track (mentioned in
   `BEHAVE-INTEGRATION.md` Out of Scope, around the
   `toolchain.c2.beacon_*` overlap with profiler's existing
   `behavioral.py`).
2. **Future BEHAVE-NETWORK extractor** parallel to BEHAVE-SHELL,
   eating PCAP / netflow / TLS-handshake records. Cleaner long-term
   architecture; substantial effort.

Either way, **not extractor work for this doc.**

## Confidence convention

Every emitted Observation must carry a `confidence` in `[0.0, 1.0]`.
Three rules:

1. **Sample-size honesty.** A primitive computed from < 5 samples
   gets `confidence ≤ 0.5`. A bucket-classification with no IATs
   should emit `unknown` (where the registry permits) at
   `confidence = 1.0` — the *fact* of insufficient data is itself a
   high-confidence observation.
2. **Threshold proximity.** If the measured value is within 10% of a
   bucket boundary, drop confidence by 0.2. Sitting on the fence is a
   real signal; pretending you know is dishonest.
3. **Output-stream availability.** Primitives that need `[t,"o",d]`
   events drop confidence to 0.0 and skip emission entirely if the
   shard contains no output events. Don't fabricate.

Confidence is **the sensor's confidence in its measurement**, not in
any downstream verdict — same line BEHAVE draws.

---

## The route to v0 — every Tier-A primitive emits

**v0 ships the entire BEHAVE-SHELL Tier-A corpus.** All 37
shell-extractable primitives in the registry must have a feature
function emitting them before the engine tags v0. Anything less is
v0-pre.

The route is broken into **eight phases (A–H)** that each ship a
coherent slice with its own tests. With the architecture locked
(`SessionContext`, `_features/`, `_thresholds.py` already designed),
each primitive is a small, well-bounded chunk — most are dozens of
lines plus tests. The two real cost centres are Phase F (prompt
parser) and Phase G (command-intent lexicon); both bounded by the
calibration notes already in the registry. Phase A establishes the
6-primitive calibration floor (the discriminative grid). Phases B–G
expand horizontally across the registry. Phase H is the full-corpus
lockdown + v0 release.

Each step within a phase is one commit (per the "commit per task"
memory rule), with its own tests in the same commit (per "tests per
task"). No step is allowed to land red against the calibration grid
once Phase A locks it in.

### Phase A — Calibration floor (Steps 0–10)

**Goal:** establish the 6-primitive set that discriminates the
five-class calibration grid. Lock the gate.

This is the foundation. Phases B–G cannot start until Phase A green.

### Step 0 — Scaffold + smoke

**Goal:** prove the wiring before any logic.

- Create `decnet/profiler/behave_shell/{__init__,extract,_parse,_ctx,_thresholds}.py`.
- `extract_session()` parses events into a minimal `SessionContext`,
  registers an empty `FEATURES = ()`, returns no observations.
- `tests/profiler/behave_shell/test_extract_smoke.py` asserts:
  - empty events → empty iterable
  - one input event → SessionContext built, t_start/t_end/duration_s correct
  - import path works

Commit message: `feat(profiler/behave_shell): scaffold extract_session entry point`.

### Step 1 — Asciinema parser + paste-burst detector

**Goal:** the shared primitives that two feature modules will consume.

- `_parse.py`: types (`InputEvent`, `OutputEvent`, `PasteBurst`,
  `Command`) + `parse_event(line: str | dict) -> AsciinemaEvent`.
- `_ctx.py`: `build_session_context()` populates `iats`,
  `paste_bursts` (chunks where consecutive IATs < `PASTE_IAT_MAX_S`
  AND chunk size > `PASTE_MIN_CHARS`).
- Tests: synthetic streams covering pure-typed, pure-pasted, mixed.

Commit: `feat(profiler/behave_shell): asciinema parser + paste-burst detection`.

### Step 2 — `motor.input_modality` (FIRST PRIMITIVE)

**Goal:** prove the end-to-end pipeline emits a single registry-valid
Observation.

Why first: highest discriminative value (HUMAN vs everyone), simplest
implementation (just count paste-burst chars vs typed chars).

- `_features/motor.py:input_modality(ctx)` yields one Observation
  with value in `{"typed", "pasted", "mixed"}`.
- Register in `FEATURES`.
- Tests:
  - synthetic typed stream → `typed`
  - synthetic pasted stream → `pasted`
  - HUMAN calibration shard → `typed`
  - YOU-sim calibration shard → `pasted`

After this step, the calibration grid passes for **one column** and
the integration is end-to-end live (Phase 4 of the integration plan
becomes wireable, not just blocked on theory).

Commit: `feat(profiler/behave_shell): emit motor.input_modality`.

### Step 3 — `motor.paste_burst_rate`

**Goal:** second primitive, builds on the paste-burst index from
step 1. Splits YOU-sim from LW/CLAUDE-FF/CLAUDE-CL.

- `_features/motor.py:paste_burst_rate(ctx)` → `none / occasional / habitual`.
- Threshold constants in `_thresholds.py`.
- Tests + grid extension.

Commit: `feat(profiler/behave_shell): emit motor.paste_burst_rate`.

### Step 4 — Command segmentation (no primitive)

**Goal:** shared utility for the three cognitive primitives next in
line. Pure refactor inside `_ctx.py`.

- `commands` populated: split input stream on `\r` (and `\n`) into
  `Command(start_ts, end_ts, first_token_hash)` records.
- **PII discipline:** store only the *first token* (or its hash) plus
  timing. Never the full command body. Branch-diversity needs the
  first token; nothing needs the rest.
- `inter_cmd_iats` and `output_per_cmd` populated.
- Tests for segmentation edge cases (no trailing newline, multiple
  newlines in a paste, etc).

Commit: `feat(profiler/behave_shell): command segmentation in SessionContext`.

### Step 5 — `cognitive.inter_command_latency_class`

**Goal:** classify the operator's *thinking pace* between commands.
Splits LW-sim / CLAUDE-FF / CLAUDE-CL.

- `_features/cognitive.py:inter_command_latency_class(ctx)` →
  `instant / typing_speed / deliberate / llm_lightweight / llm_heavyweight / long`.
- Median of `inter_cmd_iats`, bucketed against `_thresholds.py`.
- Confidence drops if < 5 commands.
- Tests + grid extension.

Commit: `feat(profiler/behave_shell): emit cognitive.inter_command_latency_class`.

### Step 6 — `cognitive.command_branch_diversity`

**Goal:** content-based playbook-vs-adaptive split. Splits CLAUDE-FF
from CLAUDE-CL.

- `_features/cognitive.py:command_branch_diversity(ctx)` →
  `linear_playbook / adaptive_branching / unknown`.
- `unique_first_tokens / total_commands` ratio against threshold.
- `unknown` when total_commands < 5 (registry-allowed).
- Tests + grid extension.

Commit: `feat(profiler/behave_shell): emit cognitive.command_branch_diversity`.

### Step 7 — `cognitive.feedback_loop_engagement`

**Goal:** the orthogonal axis — does the operator's pause-after-command
correlate with output bytes? Splits HUMAN/CLAUDE-CL (closed) from
LW-sim/CLAUDE-FF (fire-and-forget).

- Requires `output_per_cmd[i]` paired with `inter_cmd_iats[i+1]`.
- Pearson correlation; bucket on r > 0.3 / r ≈ 0 / insufficient.
- `_features/cognitive.py:feedback_loop_engagement(ctx)` →
  `closed_loop / fire_and_forget / unknown`.
- **First primitive that depends on output events.** If the shard
  carries no `'o'` events (rare but possible — minimal recorders),
  emit `unknown` at confidence 1.0.
- Tests + grid extension.

Commit: `feat(profiler/behave_shell): emit cognitive.feedback_loop_engagement`.

### Step 8 — `cognitive.inter_command_consistency`

**Goal:** dispersion/bimodality of command IATs.
HUMAN-bimodal vs LLM-metronomic.

- CV of `inter_cmd_iats` → `metronomic` (CV < 0.2) /
  `variable` (0.2 ≤ CV < 1.0) / `bimodal` (CV ≥ 1.0 OR Hartigan dip
  significant — v0.1 is CV-only, registry note flags v0.2 work).
- Tests + grid extension.

Commit: `feat(profiler/behave_shell): emit cognitive.inter_command_consistency`.

### Step 9 — Calibration grid lockdown

**Goal:** the gate. After this step lands, no engine PR is allowed
to drop a primitive from any of the five classes.

- `tests/profiler/behave_shell/test_calibration_grid.py` parametrised
  over the five shards from `BEHAVE/prototype_extractors/shell/`.
- For each shard, assert the **required primitive set** from the
  integration doc's grid table is present in the output (subset
  check, not exact match — engine is allowed to emit *more* than
  the table requires).
- Skip with `pytest.importorskip` style if `BEHAVE_CALIBRATION_DIR`
  unset — CI provides it, dev doesn't have to.
- This is the v0 gate.

Commit: `test(profiler/behave_shell): five-class calibration grid lockdown`.

### Step 10 — Phase A complete: calibration floor locked

**Goal:** Phase A done. **NOT v0 release** — v0 requires the full
Tier-A corpus (Phases B–H below). Phase A delivers the 6-primitive
discriminative floor + the gate that future phases must not break.

- 6 primitives emitting (`motor.input_modality`,
  `motor.paste_burst_rate`,
  `cognitive.inter_command_latency_class`,
  `cognitive.command_branch_diversity`,
  `cognitive.feedback_loop_engagement`,
  `cognitive.inter_command_consistency`).
- Calibration grid green across all five class shards.
- Worker can be wired against Phase A safely
  (BEHAVE-INTEGRATION.md Phase 4 unblocks here, *not* at v0).

Commit: `feat(profiler/behave_shell): Phase A — calibration floor green`.

---

### Phase B — `motor.*` completion (4 primitives)

**Goal:** finish the motor family minus shell-mastery. All four
read existing `SessionContext` derived data; no new parsing.

| Step | Primitive | Source | Notes |
|---|---|---|---|
| B.1 | `motor.keystroke_cadence` | `ctx.iats` histogram shape | steady (uniform) / bursty (heavy-tailed) / hunt_and_peck (bimodal slow+fast) / machine (sub-typing-floor) |
| B.2 | `motor.motor_stability` | `ctx.iats` outlier rate | tremor = high-frequency outliers above CV-of-IATs threshold |
| B.3 | `motor.error_correction` | backspace events relative to preceding key | immediate (<500ms) / deferred (next word boundary) / absent / route_around (no backspaces, but command later replaced) |
| B.4 | `motor.command_chunking` | per-command IAT variance + word-boundary timing | fluent (low intra-cmd variance + tight word boundaries) / fragmented (high variance) / single_command (one-shot session) |

Per-step deliverable: feature function in `_features/motor.py`,
threshold constants in `_thresholds.py`, unit tests against
synthetic streams, calibration grid still green.

Commits (4): `feat(profiler/behave_shell): emit motor.{keystroke_cadence,motor_stability,error_correction,command_chunking}`.

### Phase C — `motor.shell_mastery.*` (3 primitives)

**Goal:** the shell-fluency block. Per-command counters; trivial
implementations once command segmentation is in place (Step 4).

| Step | Primitive | Source |
|---|---|---|
| C.1 | `motor.shell_mastery.tab_completion` | `\t` rate per command (none / occasional <30% / habitual ≥50%) |
| C.2 | `motor.shell_mastery.shortcut_usage` | ^A/^E/^W/^U/^R/^B/^F rate (none / moderate / heavy) |
| C.3 | `motor.shell_mastery.pipe_chaining_depth` | `\|` count per command, median (shallow / moderate / deep) |

Commits (3): `feat(profiler/behave_shell): emit motor.shell_mastery.*`.

### Phase D — `cognitive.*` completion (8 primitives)

**Goal:** finish the cognitive family. Mix of cheap and expensive;
`cognitive_load` is a composite over earlier primitives.

| Step | Primitive | Source | Cost |
|---|---|---|---|
| D.1 | `cognitive.cognitive_load` | composite: IAT entropy + error rate + chunking variance | MEDIUM |
| D.2 | `cognitive.exploration_style` | command-graph branching shape (revisits, backtracks) | MEDIUM |
| D.3 | `cognitive.planning_depth` | think-pause-length distribution; deep = many >1.5s gaps before commands | LOW |
| D.4 | `cognitive.tool_vocabulary` | distinct first-tokens normalised by session length | LOW |
| D.5 | `cognitive.error_resilience.retry_tactic` | post-error command relation: rerun (same), modify (edit-and-retry), switch (different tool), abort (exit) | MEDIUM |
| D.6 | `cognitive.error_resilience.frustration_typing` | error-vs-success keystroke speed delta | LOW |
| D.7 | `cognitive.error_resilience.fallback_to_man` | `man`/`--help`/`-h` invocation post-error | LOW |
| D.8 | `cognitive.cognitive_load` re-tune (gate) | re-run calibration once D.1-D.7 stable | — |

Commits (7): one per primitive, plus a re-tune commit if needed.

### Phase E — `temporal.*` per-session subset (4 primitives)

**Goal:** the four temporal primitives that don't need observation
history. The other three temporal primitives (session_timing,
persistence, idle_periodicity) are **Tier B** and are filed in
`ATTRIBUTION-ENGINE.md` — do not implement here.

| Step | Primitive | Source | Cost |
|---|---|---|---|
| E.1 | `temporal.session_duration` | `ctx.duration_s` bucketed (short <60s / medium <600s / long <3600s / marathon ≥3600s) | TRIVIAL |
| E.2 | `temporal.escalation_pattern` | command-rate over rolling windows (sustained / erratic / bursty) | LOW |
| E.3 | `temporal.lifecycle_markers.landing_ritual` | first-N-commands signature match (`uname` / `id` / `whoami` / `pwd`) | LOW |
| E.4 | `temporal.lifecycle_markers.exit_behavior` | last command + exit timing (graceful `exit`/`logout` / abrupt session-cut / cleanup `history -c` etc.) | LOW |

Commits (4): per primitive.

### Phase F — `environmental.*` output-stream block (5 primitives)

**Goal:** the output-stream-dependent cluster. Lands a shared
prompt-string parser once, then five primitives consume it. **This
is the most expensive single phase** — the prompt parser has to
handle ANSI escape sequences, multi-line continuation, and
custom prompts.

| Step | Primitive | Source | Cost |
|---|---|---|---|
| F.0 | Prompt-string parser (`_parse.py`) | shared utility, no primitive | HIGH |
| F.1 | `environmental.shell_type` | prompt suffix sniff (`$`/`#`/`%`/`>`) + command syntax (bash / zsh / fish / cmd / powershell) | MEDIUM |
| F.2 | `environmental.terminal_multiplexer` | tmux/screen-specific escape sequences in output stream | LOW |
| F.3 | `environmental.locale` | `LANG`/`LC_*` envvars if attacker dumps env; output language sniff fallback (free string, BCP-47) | MEDIUM |
| F.4 | `environmental.keyboard_layout` | bigram-frequency fingerprint against known layouts (qwerty / azerty / qwertz / other) | HIGH |
| F.5 | `environmental.numpad_usage` | numeric input arrival pattern; weak signal — confidence cap | LOW |

Commits (6): F.0 prepares; F.1-F.5 ship one per primitive.

### Phase G — `operational.*` + `emotional_valence.*` (8 primitives)

**Goal:** the two soft families. Both want a small command-intent /
sentiment lexicon; combine into one phase to share the lexical
infrastructure.

| Step | Primitive | Source | Cost / Confidence |
|---|---|---|---|
| G.0 | Command-intent lexicon (`_features/_intent.py`) | shared first-token → category mapping (recon / exfil / persistence / lateral / destructive) | HIGH (corpus building) |
| G.1 | `operational.objective` | majority-category over session commands | MEDIUM |
| G.2 | `operational.opsec_discipline` | history-clearing / log-tampering / `.bash_history` removal patterns | MEDIUM |
| G.3 | `operational.cleanup_behavior` | exit-time cleanup commands (`rm`-of-touched-files, `unset HISTFILE`) | MEDIUM |
| G.4 | `operational.multi_actor_indicators` | mid-session pace/style shift detection (only `solo` and `handoff_detected` honest single-session; `team_coordinated` is Tier B) | HIGH |
| G.5 | `emotional_valence.valence` | lexical sentiment; positive / neutral / negative — **CONFIDENCE CAP 0.5** | LOW (soft) |
| G.6 | `emotional_valence.arousal` | typing-speed delta + capslock + repeated bangs — **CAP 0.5** | LOW (soft) |
| G.7 | `emotional_valence.stress_response` | post-error speed-up (distress) vs slow-down (eustress) — **CAP 0.5** | LOW (soft) |
| G.8 | `emotional_valence.frustration_venting` | obscenity detection (`fuck`/`shit`/`damn`); registry value is binary — **CAP 0.5** | LOW (soft) |

Commits (9). All four `emotional_valence.*` primitives ship under a
**hard 0.5 confidence cap** by convention — these are the most
likely primitives to embarrass the project, and operators must not
act on them without corroboration.

### Phase H — Full-corpus lockdown + v0 release

**Goal:** prove every Tier-A primitive in the registry has a feature
function, tag v0.

| Step | Action |
|---|---|
| H.1 | **Registry-coverage test**: `tests/profiler/behave_shell/test_registry_coverage.py` walks `PRIMITIVE_REGISTRY`, filters out Tier-B and Tier-C primitives (explicit allow-list), asserts every remaining primitive appears in the output of at least one calibration shard. CI fails if the registry adds a primitive DECNET hasn't implemented yet. |
| H.2 | **Calibration grid full sweep**: re-run the five-class grid against the full primitive set; no regressions. |
| H.3 | **Live smoke**: ship a decky, run a real session from each calibration class, observe full primitive output in `observations` table + bus + AttackerDetail panel (mirrors integration-doc Phase 6). |
| H.4 | **Worker wired** (BEHAVE-INTEGRATION.md Phase 4 unblocks here). Pin `decnet-behave-core` / `decnet-behave-shell` in `pyproject.toml`. |
| H.5 | Tag v0; add `__version__ = "0.1.0"` to `behave_shell/__init__.py`. |

Commit: `feat(profiler/behave_shell): v0 — full Tier-A corpus, all 37 primitives emitting`.

### Per-phase rules (binding for all of B–H)

1. **Calibration-grid gate is binding.** Every commit in B–G runs
   the grid; any drop in expected primitive sets fails CI.
2. **Registry-coverage test is binding from H onward.** New Tier-A
   primitives added to BEHAVE's registry without a corresponding
   DECNET feature function fail CI.
3. **Adding a primitive = adding a feature func + registering it +
   threshold constants + tests in the same commit.** No sneaking
   implementation in without tests, no sneaking tests in without the
   calibration assertion.
4. **Phases B–G can ship in any order**, but finish a phase before
   starting another. Phase F is the hardest and should be sequenced
   by reader stamina, not enthusiasm.
5. **Don't rush Phase G.** The soft primitives are the most likely
   to embarrass the project. Calibrate against real-attacker shards
   before tagging — and even then, hold the 0.5 confidence cap.
6. **Tier-B and Tier-C scope creep is forbidden.** The moment you
   feel tempted to read a SECOND session inside `extract_session()`,
   stop. That observation belongs to the attribution engine.

Don't promise a delivery date for any phase. Each lands when it's
honest. v0 ships when **every Tier-A primitive emits + every test
green** — not before.

---

## Out of scope for the engine

- **Attribution.** Per the integration doc's bright line. Engine
  emits observations; some other thing decides what they mean. See
  `ATTRIBUTION-ENGINE.md`.
- **Cross-session merge logic.** That's DEBT-051 / Tier-B
  primitives. Engine sees one session at a time, period.
- **Tier-C `toolchain.*` primitives.** Network-domain sensors
  (sniffer, prober, correlator) own these. Either via existing
  workers wrapping their outputs as BEHAVE observations, or a future
  BEHAVE-NETWORK extractor. Not this doc.
- **Persistence / bus.** Worker concerns. Engine is pure.
- **Dynamic primitive registration.** The `FEATURES` tuple is
  hand-edited; no plugin loaders. New primitive = new feature func +
  one-line registry edit + tests in the same commit.
- **Streaming / partial extraction.** Engine assumes a complete
  session. Live mid-session inference is a v2 concern; needs a
  separate state-keeping design.
- **`primitives.py` registry edits.** The engine consumes the
  registry; never mutates it. If a primitive is missing, file a
  BEHAVE-side commit per the integration doc's "BEHAVE-side commits"
  rule.
- **Confidence calibration against ground truth.** The calibration
  grid is a *discrimination* test, not a *correctness* test. True
  ground-truth labels would require red-team exercises with logged
  intent. Filed when that data exists.

---

## Implementation order checklist

A single page you can paste into a TODO and tick off. **Every box
unchecked = no v0 tag.**

### Phase A — Calibration floor (Steps 0–10)
- [x] Step 0 — Scaffold + smoke test
- [x] Step 1 — Asciinema parser + paste-burst detector
- [x] Step 2 — `motor.input_modality` (FIRST PRIMITIVE)
- [x] Step 3 — `motor.paste_burst_rate`
- [x] Step 4 — Command segmentation in `SessionContext`
- [x] Step 5 — `cognitive.inter_command_latency_class`
- [x] Step 6 — `cognitive.command_branch_diversity`
- [x] Step 7 — `cognitive.feedback_loop_engagement`
- [x] Step 8 — `cognitive.inter_command_consistency`
- [x] Step 9 — Calibration grid lockdown (the gate)
- [x] Step 10 — Phase A complete: floor green

### Phase B — `motor.*` completion
- [x] B.1 `motor.keystroke_cadence`
- [x] B.2 `motor.motor_stability`
- [x] B.3 `motor.error_correction`
- [x] B.4 `motor.command_chunking`

### Phase C — `motor.shell_mastery.*`
- [x] C.1 `motor.shell_mastery.tab_completion`
- [x] C.2 `motor.shell_mastery.shortcut_usage`
- [x] C.3 `motor.shell_mastery.pipe_chaining_depth`

### Phase D — `cognitive.*` completion
- [ ] D.1 `cognitive.cognitive_load`
- [ ] D.2 `cognitive.exploration_style`
- [ ] D.3 `cognitive.planning_depth`
- [ ] D.4 `cognitive.tool_vocabulary`
- [ ] D.5 `cognitive.error_resilience.retry_tactic`
- [ ] D.6 `cognitive.error_resilience.frustration_typing`
- [ ] D.7 `cognitive.error_resilience.fallback_to_man`
- [ ] D.8 cognitive.cognitive_load re-tune (gate)

### Phase E — `temporal.*` per-session
- [ ] E.1 `temporal.session_duration`
- [ ] E.2 `temporal.escalation_pattern`
- [ ] E.3 `temporal.lifecycle_markers.landing_ritual`
- [ ] E.4 `temporal.lifecycle_markers.exit_behavior`

### Phase F — `environmental.*` (output-stream block)
- [ ] F.0 Prompt-string parser (shared utility)
- [ ] F.1 `environmental.shell_type`
- [ ] F.2 `environmental.terminal_multiplexer`
- [ ] F.3 `environmental.locale`
- [ ] F.4 `environmental.keyboard_layout`
- [ ] F.5 `environmental.numpad_usage`

### Phase G — `operational.*` + `emotional_valence.*` (soft block)
- [ ] G.0 Command-intent lexicon (`_features/_intent.py`)
- [ ] G.1 `operational.objective`
- [ ] G.2 `operational.opsec_discipline`
- [ ] G.3 `operational.cleanup_behavior`
- [ ] G.4 `operational.multi_actor_indicators`
- [ ] G.5 `emotional_valence.valence` (cap 0.5)
- [ ] G.6 `emotional_valence.arousal` (cap 0.5)
- [ ] G.7 `emotional_valence.stress_response` (cap 0.5)
- [ ] G.8 `emotional_valence.frustration_venting` (cap 0.5)

### Phase H — Full-corpus lockdown + v0 release
- [ ] H.1 Registry-coverage test
- [ ] H.2 Calibration grid full sweep, no regressions
- [ ] H.3 Live smoke across all five calibration classes
- [ ] H.4 Worker wired + `pyproject.toml` pin
- [ ] H.5 Tag v0 (`__version__ = "0.1.0"`)

**44 boxes. 37 primitives. 1 v0.** Each box is a commit + tests in
the same commit.

---

## Phase A completion log

Closed in 11 commits across one session. Six primitives emit; the
five-class calibration grid is the binding regression test for
every subsequent phase.

| Primitive | Confidence | Empirical anchor (2026-05-02 corpus) |
|---|---|---|
| `motor.input_modality` | 0.70 / 0.75 | YOU-sim 47.6% paste → ``pasted``; HUMAN <5% → ``typed`` |
| `motor.paste_burst_rate` | 0.70 / 0.80 | LW-sim / CLAUDE-FF / CLAUDE-CL ≥50% → ``habitual`` |
| `cognitive.inter_command_latency_class` | 0.40 / 0.80 | CLAUDE-FF 15.5s median → ``llm_heavyweight`` |
| `cognitive.command_branch_diversity` | 0.80 / 1.00 | CLAUDE-CL ≈0.55-0.60 → ``adaptive_branching``; threshold 0.70 |
| `cognitive.feedback_loop_engagement` | 0.75 / 1.00 | CLAUDE-FF flat r → ``fire_and_forget``; r > 0.30 → ``closed_loop`` |
| `cognitive.inter_command_consistency` | 0.40 / 0.75 | LLM CV≈0.24 → ``metronomic``; HUMAN CV≈0.94 → ``variable`` |

The hard gate (every Phase A primitive must fire per shard) is in
``tests/profiler/behave_shell/test_calibration_grid.py`` and skips
cleanly when ``BEHAVE_CALIBRATION_DIR`` is unset.

Per-class **value** pinning (e.g. HUMAN must emit
``inter_command_consistency=bimodal``) is intentionally NOT a hard
gate at this milestone — v0.1 thresholds put real human sessions
in ``variable``, and true bimodal detection (Hartigan dip /
two-peak) is registry-flagged for v0.2. Tighter pinning lands as
the corpus grows.

**Worker unblocked:** ``BEHAVE-INTEGRATION.md`` Phase 4 can now wire
the per-session producer against the Phase A engine; the Tier-A
corpus continues to grow under Phases B-G without changing the
worker's interface.

---

## Phase B completion log

Closed in 4 commits, one primitive per commit. The
``motor.*`` family (minus ``shell_mastery``) now emits.

| Primitive | Confidence | Source signal |
|---|---|---|
| `motor.keystroke_cadence` | 0.60 / 0.65 / 0.70 / 0.85 | median within-burst CV; bursts split at gaps > IKI_THINK_MAX_S; sub-5 ms mean + sub-0.05 CV → ``machine`` |
| `motor.motor_stability` | 0.60 / 0.65 / 0.70 | tremor: ≥10% within-burst IATs below 30 ms (physiologically implausible double-press); else burst-CV picks steady vs variable |
| `motor.error_correction` | 0.55 / 0.55 / 0.65 / 0.65 | backspace IAT to preceding key (≤500 ms = immediate); ^U/^W with no backspaces → route_around |
| `motor.command_chunking` | 0.60 / 0.65 / 0.80 | median CV of per-command typed IATs; 1 command → ``single_command`` |

Implementation note: B.2 and B.4 are first principled
implementations — the prototype extractor doesn't ship them. B.3
replaces the prototype's two-line "0 vs >0 backspaces" heuristic
with a full-vocabulary classifier.

PII discipline preserved across all four: only counts and timing
aggregates leave the helper functions; no character data is
retained or serialised. The PII regression for ``error_correction``
is pinned by ``test_pii_no_command_bodies_in_observation``.

**Calibration grid widened:** ``PHASE_AB_PRIMITIVES`` now contains
10 names and is binding for every subsequent phase. All five
class shards still emit every Phase A+B primitive at least once.

Phase C (``motor.shell_mastery.*``, 3 primitives) lands next.

---

## Phase C completion log

Closed in 3 commits, one primitive per commit. The
``motor.shell_mastery.*`` block now emits — three per-command counters
(`tab_count`, `shortcut_count`, `pipe_count`) populated during the
single-pass `_segment_commands()` sweep, fed to three independent
classifiers.

| Primitive | Confidence | Source signal |
|---|---|---|
| `motor.shell_mastery.tab_completion` | 0.40 / 0.55 / 0.75 | fraction of commands containing ≥1 ``\t``; <30% → occasional, ≥50% → habitual, 30%-50% gap rounds down |
| `motor.shell_mastery.shortcut_usage` | 0.40 / 0.55 / 0.65 | total readline ctrl bytes (^A/^E/^W/^U/^R/^B/^F) per command; v0.1 thresholds 0.05 / 0.30 awaiting corpus calibration |
| `motor.shell_mastery.pipe_chaining_depth` | 0.40 / 0.55 / 0.70 | median ``\|`` count across commands; 2 → moderate, ≥3 → deep; pasted pipelines count too |

Implementation note: ANTI relaxed the Phase A/B PII discipline for
this phase — full attacker profiles outweigh residual PII paranoia
on a honeypot byte stream. Even so, only **integer counters** land
on `Command`; the raw bytes are read once during the segmentation
walk and discarded. No character data is retained or serialised.

The ^U / ^W bytes that drive ``shortcut_usage`` also count toward
``motor.error_correction``'s ``kill_line_count`` channel (Step B.3).
These are independent measurements over the same byte stream — not
double-counting, just two different questions about the same key.

**Calibration grid widened:** ``PHASE_ABC_PRIMITIVES`` now contains
13 names and is binding for every subsequent phase. The set rename
from ``PHASE_AB_PRIMITIVES`` lands in C.1; downstream phases extend
the same set without renaming again until v0.

Phase D (``cognitive.*`` completion, 7+1 primitives) lands next.

---

**Owner:** ANTI.
**Implementation gate:** Step 0 starts after this doc is reviewed +
Phase 1 of `BEHAVE-INTEGRATION.md` lands (storage table exists).
