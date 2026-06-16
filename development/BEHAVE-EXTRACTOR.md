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

**Carry-overs F.0 must unblock when it lands:**

* **E.4** — `temporal.lifecycle_markers.exit_behavior` was held at
  Phase E because abrupt-vs-cleanup classification needs exit-code
  visibility (and `history -c`-style flag detection); F.0's prompt
  parser is the planned source for both. E.4 ships with the F.0
  commit (or a sibling F.0a commit) and joins the calibration grid
  binding set at that point.
* **D.0** — already landed as a forward-port. F.0 should *subsume*
  the D.0 helpers (`strip_ansi`, `_OUTPUT_ERROR_PATTERNS`,
  `detect_error_in_output`) into the prompt parser proper, replacing
  the v0.1 regex heuristic with a PS1 + exit-code sniff. The
  `Command.errored` field stays; only the population path moves.

| Step | Primitive | Source | Cost |
|---|---|---|---|
| F.0 | Prompt-string parser (`_parse.py`) — also: subsume D.0 ANSI/error helpers, unblock E.4 | shared utility, no primitive | HIGH |
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
- [x] D.0 — output error-signal helper (F.0a reorder)
- [x] D.1 `cognitive.cognitive_load`
- [x] D.2 `cognitive.exploration_style`
- [x] D.3 `cognitive.planning_depth`
- [x] D.4 `cognitive.tool_vocabulary`
- [x] D.5 `cognitive.error_resilience.retry_tactic`
- [x] D.6 `cognitive.error_resilience.frustration_typing`
- [x] D.7 `cognitive.error_resilience.fallback_to_man`
- [x] D.8 cognitive.cognitive_load re-tune (gate)

### Phase E — `temporal.*` per-session
- [x] E.1 `temporal.session_duration`
- [x] E.2 `temporal.escalation_pattern`
- [x] E.3 `temporal.lifecycle_markers.landing_ritual`
- [x] E.4 `temporal.lifecycle_markers.exit_behavior` — unblocked + landed in Phase F (uses `Command.followed_by_prompt` from F.0)

### Phase F — `environmental.*` (output-stream block)
- [x] F.0 Prompt-string parser (shared utility) — unblocked **E.4**; **D.0 enriched, not subsumed** (regex error helpers stay)
- [x] F.1 `environmental.shell_type`
- [x] F.2 `environmental.terminal_multiplexer`
- [x] F.3 `environmental.locale`
- [x] F.4 `environmental.keyboard_layout` (PII boundary lifted by ANTI; emits all 4 registry values)
- [x] F.5 `environmental.numpad_usage`

### Phase G — `operational.*` + `emotional_valence.*` (soft block)
- [x] G.0 Command-intent lexicon (`_intent.py`, **package-root** not `_features/`, to avoid the `_features/__init__.py` ↔ `_ctx.py` import cycle) + typed-text counter pass extension
- [x] G.1 `operational.objective`
- [x] G.2 `operational.opsec_discipline`
- [x] G.3 `operational.cleanup_behavior`
- [x] G.4 `operational.multi_actor_indicators` (`team_coordinated` is Tier B; never emitted from a single session)
- [x] G.5 `emotional_valence.valence` (cap 0.5)
- [x] G.6 `emotional_valence.arousal` (cap 0.5)
- [x] G.7 `emotional_valence.stress_response` (cap 0.5)
- [x] G.8 `emotional_valence.frustration_venting` (cap 0.5)

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

## Phase D completion log

Closed in 9 commits. Phase D opened with a reorder: rather than ship
the four error-aware primitives (D.1's error-rate term, D.5–D.7) on a
regex heuristic and re-tune at Phase F, the **error-signal slice of
F.0 lifted forward** as a D.0 prelude. The full prompt-string parser
(PS1 sniff, multiplexer escape, locale, layout) stays scoped to Phase
F; D.0 ships only the ANSI-strip + canonical bash/sh error fingerprint
match needed for ``Command.errored``.

D.0 — `Command` gained two fields:

* `errored: bool` — true when the post-execution output window
  contains any of the canonical fingerprints (``command not found`` /
  ``No such file or directory`` / ``Permission denied`` /
  ``: cannot `` / ``Operation not permitted`` /
  ``syntax error near unexpected token``), with ANSI sequences
  stripped first via the new `_parse.strip_ansi` helper.
* `output_bytes: int` — raw byte count of the same window (pre-strip).

PII discipline preserved: `_output_window()` discards the stripped
text on return; only the bool and the int leave the helper. Pinned by
`test_pii_no_output_bodies_in_observations` in
`tests/profiler/behave_shell/test_command_error_detection.py`.

The seven Phase D primitives:

| Primitive | Confidence | Source signal |
|---|---|---|
| `cognitive.cognitive_load` | 0.40 / 0.60 | composite of three [0,1]-clipped sub-signals (chunking CV, error rate from D.0, pace CV); components missing data drop out of the mean |
| `cognitive.exploration_style` | 0.40 / 0.60 | repetition-rate vs backtrack-rate over `first_token_hash` sequence |
| `cognitive.planning_depth` | 0.40 / 0.65 | distribution of inter-cmd IATs vs `IKI_THINK_MAX_S` (deep) and `INTER_CMD_INSTANT_MAX` (reactive) |
| `cognitive.tool_vocabulary` | 0.40 / 0.70 | absolute distinct-`first_token_hash` count (≤3 narrow, ≥10 broad) |
| `cognitive.error_resilience.retry_tactic` | 0.40 / 0.65 | modal post-error response: same-token rerun, different-token switch, no-next-command abort. `modify` deferred to v0.2 (PII boundary) |
| `cognitive.error_resilience.frustration_typing` | 0.40 / 0.60 | relative delta of median within-command IAT post-error vs post-success |
| `cognitive.error_resilience.fallback_to_man` | 0.40 / 0.65 | post-error `first_token_hash` ∈ {`man`, `help`, `info`} (precomputed at module load); `--help`/`-h` flag forms deferred to v0.2 |

**Re-tune at D.8 (the "gate"):** without the calibration shards on
disk in this checkout (`BEHAVE_CALIBRATION_DIR` unset), an empirical
re-tune of `COGNITIVE_LOAD_*` thresholds is filed for the next
calibration-shards run. The v0.1 thresholds ship; D.8 in this commit
widens the calibration grid binding set
(`PHASE_ABC_PRIMITIVES` → `PHASE_ABCD_PRIMITIVES`) and pins the four
unconditional Phase D primitives as required-emission. The three
`cognitive.error_resilience.*` primitives are **conditional** on
errored commands existing in a shard — they're tracked in
`PHASE_D_CONDITIONAL_PRIMITIVES` and excluded from the per-shard hard
gate (a clean shard with zero errors can't honestly emit them).

**Calibration grid widened:** the binding set now contains 17 names.
Phase E (`temporal.*` per-session subset, 4 primitives) lands next.

---

## Phase E completion log

Closed in 4 commits, **3 of 4 primitives shipping**. ANTI ruled E.4
(`temporal.lifecycle_markers.exit_behavior`) **held** at planning
time: the abrupt / graceful / cleanup distinction needs exit-code
visibility, and that infrastructure lands as part of Phase F.0's
prompt parser. First-token membership alone is too noisy in both
directions (`rm` / `clear` mid-session over-fire as cleanup; `history
-c` under-fires because flag detection crosses v0.1's PII boundary).
E.4 unblocks once F.0's PS1 + exit-code sniff is wired.

The three Phase E primitives that did ship:

| Primitive | Confidence | Source signal |
|---|---|---|
| `temporal.session_duration` | 0.85 | `ctx.duration_s` bucketed against 60s / 600s / 3600s; direct measurement, not an inference. |
| `temporal.escalation_pattern` | 0.40 / 0.60 | Non-overlapping windows of width `max(10s, duration_s/10)`; CV of per-window counts + zero-window fraction → bursty / sustained / erratic. |
| `temporal.lifecycle_markers.landing_ritual` | 0.40 / 0.65 | Hits in first `N=5` commands against precomputed hashes of `{uname, id, whoami, pwd, hostname, w, who}`; `≥ K=2` hits → present. |

Implementation note: the new `_features/temporal.py` module mirrors
the `_features/cognitive.py` layout; recon-vocabulary hashes are
precomputed at module load (single sha256 sweep at import) so the
hot path is a frozenset membership test. `math.ceil`-based window
counting in E.2 avoids a phantom trailing zero bin on clean
divisions — a real bug that test_temporal_escalation_pattern.py's
erratic-case fixture flushed out during initial run.

PII discipline preserved across all three: only counts, durations,
and category labels leave the helpers; no command bodies, no output
text, no operator-identifying data.

**Calibration grid widened:** the binding set now contains 20 names
(`PHASE_ABCDE_PRIMITIVES`). The three Phase D `error_resilience.*`
primitives remain conditional in `PHASE_D_CONDITIONAL_PRIMITIVES`
(only fire on shards with at least one errored command). E.4 is
explicitly **not** in either set — it must not be referenced as a
required primitive until Phase F.0 lands.

Phase F (`environmental.*` output-stream block, 5 primitives plus
F.0's prompt parser) lands next; E.4 picks up at the tail of Phase F.

---

## Phase F completion log

Closed in 8 commits. The largest phase in the plan; the held E.4
(`temporal.lifecycle_markers.exit_behavior`) lifted at the tail.

**F.0 — prompt-line detector (no primitive).** PS1 prompt-line
detection over ANSI-stripped output. New `PromptLine` dataclass on
`SessionContext.prompt_lines` and `Command.followed_by_prompt`
populated during the existing single-pass output-window walk. Capped
at `PROMPT_LINE_MAX_CHARS = 256` to bound memory.

**Reversal of the original BEHAVE-EXTRACTOR.md F.0 hint:** D.0 is
**enriched, not subsumed**. The regex error fingerprints catch errors
even when PS1 echo is suppressed (custom prompts, non-interactive
exec) where prompt-based detection would miss. F.0 is purely
additive.

**PII boundary lift.** ANTI authorised dropping the v0.1 PII boundary
for Phase F: PromptLine retains hostnames / cwd / etc. (capped),
parsed locale envvar values ride on observations, F.4 retains typed
bigram/unigram histograms on `SessionContext`. The discipline kept is
"no FULL command bodies, no FULL output bodies in observations" —
PromptLine and histograms live on ctx but are never serialised into
observation values; only derived primitive values (`bash`, `en-US`,
`qwerty`, `present`) leave the engine.

The five Phase F primitives + carry-over E.4:

| Primitive | Confidence | Source signal |
|---|---|---|
| `environmental.shell_type` | 0.40 / 0.75 | per-prompt-line classification; mode of suffix character with `>` disambiguated by content (`PS ` → powershell, `C:\` → cmd.exe, else fish) |
| `environmental.terminal_multiplexer` | 0.55 / 0.85 | scan RAW output for tmux markers (DCS passthrough, focus-reporting, window-title), screen markers (DCS, screen-OSC); both → prefer tmux |
| `environmental.locale` | 0.80 | regex match `LANG=` / `LC_ALL=` / `LC_CTYPE=` in stripped output; LC_ALL > LANG > LC_CTYPE; POSIX → BCP-47 normalisation |
| `environmental.keyboard_layout` | 0.40 / 0.55 | typed bigram/unigram histograms; layout-artefact unigrams (`q`, `z`/`y`) take priority over English-bigram saturation |
| `environmental.numpad_usage` | 0.50 | sliding window over single-char digit input events; ≥4 contiguous events with all-fast IATs (≤50ms) → detected |
| `temporal.lifecycle_markers.exit_behavior` | 0.45 / 0.65 | resolution of the E.4 hold; uses `Command.followed_by_prompt` to distinguish `abrupt` from `cleanup`/`graceful` |

**Calibration grid widened:** the binding set now contains 25 names
(`PHASE_ABCDEF_PRIMITIVES`). The three Phase D `error_resilience.*`
primitives stay in `PHASE_D_CONDITIONAL_PRIMITIVES`;
`environmental.locale` joins a new `PHASE_F_CONDITIONAL_PRIMITIVES`
since it only fires on shards containing an env / locale dump.

**Tier-A corpus delta:** 25 of 37 Tier-A primitives now emit. Phase G
(`operational.*` + `emotional_valence.*`, 8 primitives + the
command-intent lexicon) lands next. Phase H is full-corpus lockdown
+ v0 release.

## Phase G completion log

Phase G ships the soft block — four `operational.*` primitives and
four `emotional_valence.*` primitives. All four `emotional_valence.*`
ride a hard 0.5 confidence cap enforced inside the feature functions
themselves (a local `_cap_soft()` helper in
`_features/emotional_valence.py`); sample-size honesty can pull
confidence below 0.5, but never above.

**Commits (9):**

* G.0 — `decnet/profiler/behave_shell/_intent.py` ships five
  precomputed first-token-hash sets (`recon` / `exfil` / `persistence`
  / `lateral` / `destructive`) with documented precedence
  (`destructive > persistence > exfil > lateral > recon`), an
  `OPSEC_HISTORY_TOKENS` set, and three lexeme sets (positive /
  negative / obscenity). The same single-pass walk in
  `_typed_char_histograms()` now also maintains five integer counters
  (`obscenity_hits`, `positive_lex_hits`, `negative_lex_hits`,
  `caps_run_max`, `bang_run_max`) — ANTI's F-phase PII relaxation
  carries forward as fixed-vocabulary integer counters. Stop words
  that collide with registry value vocabulary (`no` / `hell` / `ok`)
  are deliberately excluded; the PII regression test catches such
  collisions. **Important:** `_intent.py` lives at the **package root**,
  not under `_features/`, because Python imports the package's
  `__init__.py` whenever a submodule is loaded — placing intent under
  `_features/` would have triggered the `_features/__init__.py` →
  `_ctx.py` → `_features._intent` → `_features/__init__.py` cycle.
* G.1 — `operational.objective`. Per-command intent classification
  via `classify_intent()`; majority vote across classified commands.
  Skip emission below `INTENT_MIN_COMMANDS=3` classified hits.
  Confidence 0.40 below `INTENT_FULL_CONFIDENCE_MIN=6`, 0.60 above.
* G.2 — `operational.opsec_discipline`. Three buckets driven by
  `OPSEC_HISTORY_TOKENS` hits and tail-K (`EXIT_BEHAVIOR_LOOKBACK_K=3`)
  cleanup vocabulary co-occurrence. `_CLEANUP_TOKEN_HASHES` is
  re-imported from `_features/temporal.py` rather than redefined.
  Confidence 0.45; 0.30 below `MIN_COMMANDS_FOR_FULL_CONFIDENCE=5`.
* G.3 — `operational.cleanup_behavior`. Three buckets over the
  tail-`CLEANUP_TAIL_K=5` commands by distinct cleanup-family hash
  count; `thorough` ≥ 3 distinct, `partial` 1-2, `none` 0. Adjacent
  to E.4's binary `exit_behavior=cleanup` — both ride. Confidence
  0.55 above 8 commands, 0.35 below.
* G.4 — `operational.multi_actor_indicators`. First-half vs
  second-half median intra-command IAT comparison; `handoff_detected`
  when both halves have ≥ `MULTI_ACTOR_HALF_MIN_COMMANDS=4` AND the
  relative delta exceeds `MULTI_ACTOR_HANDOFF_DELTA=0.5`. Skip below
  `MULTI_ACTOR_MIN_COMMANDS=8` total commands.
  **`team_coordinated` is Tier B (cross-session) and never emitted
  from a single session.** Confidence 0.55 with both halves ≥ 8;
  0.40 otherwise.
* G.5 — `emotional_valence.valence`. Pure ratio over G.0 lexical
  counters: `positive` if `positive_lex_hits` outweighs the
  `negative + obscenity` sum AND ≥ `VALENCE_MIN_HITS=2`; symmetric
  for `negative`; else `neutral`. Skip below
  `VALENCE_MIN_TYPED_CHARS=80`. Capped at 0.5; 0.30 below
  `VALENCE_FULL_CONFIDENCE_MIN=200`.
* G.6 — `emotional_valence.arousal`. Three buckets driven by typing
  speed (fastest/slowest qualifying burst median IAT) AND the G.0
  caps-run / bang-run counters. `high_agitated` fires when caps_run ≥
  5 OR bang_run ≥ 3 OR fastest median IAT < 0.06s with ≥ 30 IATs;
  `low_calm` when slowest median IAT > 0.30s with ≥ 30 IATs; else
  `medium_engaged`. Capped at 0.5; 0.30 below `AROUSAL_MIN_IATS=30`.
* G.7 — `emotional_valence.stress_response`. Compare median post-error
  intra-command IATs (commands immediately following an errored one)
  to the baseline (commands not following an error). `eustress_positive`
  when ratio ≥ 1.20; `distress_negative` when ratio ≤ 1/1.20; else
  `none`. Capped at 0.5; 0.30 below
  `STRESS_MIN_ERRORED_WITH_IATS=2` qualifying errored commands.
* G.8 — `emotional_valence.frustration_venting`. Binary read of
  `ctx.obscenity_hits`: `detected` if ≥ 1, `none` otherwise. Skip
  below `FRUST_VENT_MIN_TYPED_CHARS=30`. Capped at 0.5; 0.40 when
  detected, 0.50 only when cleanly absent over ≥ 200 typed letters,
  0.30 otherwise.

**Calibration grid widened:** the binding set is now
`PHASE_ABCDEFG_PRIMITIVES` (28 names in the per-shard hard gate).
Older `PHASE_ABCDEF_PRIMITIVES` remains as a backwards-compat alias.
Three new Phase G primitives ride the hard gate
(`operational.opsec_discipline`, `operational.cleanup_behavior`,
`emotional_valence.stress_response`); the rest of Phase G ride a new
`PHASE_G_CONDITIONAL_PRIMITIVES` set because their sample-size floors
(≥ 3 classified commands for `objective`, ≥ 8 commands for
`multi_actor_indicators`, typing bursts for `arousal`, typed-letter
floors for `valence` and `frustration_venting`) make them legitimately
absent from short shards.

**Out-of-scope reaffirmed:** `team_coordinated` multi-actor value
(Tier B); `--help` / `-h` flag detection (still v0.2 — only
`first_token_hash` retained, not arg hashes); emotion above 0.5
confidence (registry-pinned ceiling, never relaxed).

**Side fixup:** the pre-commit hook caught a previously-clean CVE
(`CVE-2026-42304` in `twisted 25.5.0`); G.0's commit bumps
`twisted >= 26.4.0rc2` and adjusts a `# type: ignore` code on
`decnet/templates/ftp/server.py:149` to match the new Twisted typing.

**Tier-A corpus delta:** **all 37 Tier-A primitives now emit** (up
from 25). Phase H is full-corpus lockdown + v0 release. Tier B
(`temporal.session_timing`, `temporal.persistence`,
`temporal.lifecycle_markers.idle_periodicity`, the four `cultural.*`
primitives, and the `team_coordinated` value of
`operational.multi_actor_indicators`) remains the attribution
engine's job — never the extractor's.

## Phase H step log (extractor-slice)

Phase H ships in two slices: an **extractor slice** (H.1, H.2, and a
`0.1.0-pre` version marker) closing the engine itself, and an
**integration slice** (H.3 live smoke + H.4 worker wiring + H.5
proper v0 tag) that rides `BEHAVE-INTEGRATION.md` Phase 4. This log
covers the extractor slice.

### H.1 — Registry-coverage test

`tests/profiler/behave_shell/test_registry_coverage.py` walks
`PRIMITIVE_REGISTRY` and asserts every Tier-A primitive has a slot
in the calibration grid (hard or conditional). Tier B
(8 cross-session primitives) is excluded by an explicit allow-list;
Tier C (`toolchain.*`) is excluded by prefix. Three checks ride:
forward (every Tier-A covered), reverse (no extractor-set drift from
the registry), and a `len(tier_a) == 37` invariant. CI now fails
before a registry addition can ship without a feature function.

### H.2 — Calibration grid full sweep (2026-05-02 corpus)

Shards at `/home/anti/Tools/BEHAVE/prototype_extractors/shell/` —
five classes, 15 sessions total. Per-class observation counts:

| Class | Sessions | Observations | Distinct primitives |
|---|---|---|---|
| HUMAN | 1 | 34 | 34 |
| YOU-sim | 2 | 59 | 34 |
| LW-sim | 5 | 136 | 34 |
| CLAUDE-FF | 3 | 84 | 34 |
| CLAUDE-CL | 4 | 111 | 34 |

**One real-shard regression surfaced and fixed:**
`environmental.keyboard_layout` was on the per-shard hard gate but
the calibration corpus maxes at ~90 typed letters per session — well
below `LAYOUT_MIN_TYPED_LETTERS=200`. Most input on these
SSH-recon shards is *pasted*, not typed. The honest fix per the
per-phase rule "v0 ships when honest, not when convenient" is to
move `environmental.keyboard_layout` from `PHASE_ABCDEFG_PRIMITIVES`
to `PHASE_F_CONDITIONAL_PRIMITIVES`, alongside `environmental.locale`.
The 200-letter floor stays — the keyboard-layout signal genuinely
needs richer typed text than this corpus has, and tuning the
threshold to pass would corrupt the signal.

**Three Tier-A primitives never fire across the 2026-05-02 corpus,
all conditional and all expected:**

* `cognitive.error_resilience.frustration_typing` — needs ≥ 2
  errored commands plus successful baseline (Phase D conditional).
* `environmental.locale` — needs an `env` / `locale` / `printenv`
  dump in the output stream (Phase F conditional).
* `environmental.keyboard_layout` — needs ≥ 200 typed letters
  per session (Phase F conditional after H.2).

The hard gate (28 primitives) fires on every shard with commands;
the discrimination smoke-check passes too. No threshold re-tunes
needed for D / F / G — the corpus surfaced the keyboard_layout shape
mismatch only.

**Calibration-grid binding update.** `PHASE_ABCDEFG_PRIMITIVES`
shrinks 28 → 27 (keyboard_layout moves to conditional);
`PHASE_F_CONDITIONAL_PRIMITIVES` grows 1 → 2.

### H.5-pre — Extractor version marker

`decnet/profiler/behave_shell/__init__.py` exports
`__version__ = "0.1.0-pre"`. The `-pre` suffix is honest: the
**extractor** is feature-complete (37/37 Tier-A primitives emit, all
green tests, calibration grid honest), but the *engine package* —
worker wiring, observations-table writes, AttackerDetail panel —
still rides the integration track. The actual `0.1.0` tag bumps the
suffix off only after `BEHAVE-INTEGRATION.md` Phase 4 lands.

**Tier-A corpus delta (final extractor-slice):** all 37 of 37
primitives have a feature function; **27** ride the per-shard hard
gate (28 pre-H.2; keyboard_layout moved out); **10** ride conditional
sets. Phase H integration slice (H.3 + H.4 + proper H.5 tag) is its
own plan.

---

## Post-v0 addition — `motor.digraph_simhash` (38th Tier-A primitive)

Added in behave-shell 0.1.2 (the v0 corpus above was 37). It is the
**keystroke-rhythm biometric**: a 64-bit Charikar SimHash of the
operator's per-digraph (two-key) flight times, bucketed per character
pair. Locality-sensitive — the same typist lands Hamming-close across
sessions and decoys, so it links one human behind multiple identities.

- **Extractor:** `_features/motor.py:digraph_simhash`, `ValueKind.HASH`,
  conditional (rides `MIN_DIGRAPHS_FOR_SIMHASH` / `MIN_DIGRAPH_SAMPLES`
  floors; lives in `PHASE_G_CONDITIONAL_PRIMITIVES`). Live-typed input
  only — pastes/escape bursts break the digraph chain.
- **Rollup:** the identity clusterer folds the session SimHashes into a
  bitwise-majority centroid written to `AttackerIdentity.kd_digraph_simhash`;
  the campaign clusterer adds a Hamming-proximity edge. STIX export
  carries the centroid (hex). Tier-A count is now **38**.

---

**Owner:** ANTI.
**Implementation gate:** Step 0 starts after this doc is reviewed +
Phase 1 of `BEHAVE-INTEGRATION.md` lands (storage table exists).
