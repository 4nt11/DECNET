# Tech debt — recurring + scheduled work

This file is the canonical home for known tech debt that has a
specific cadence, expiry, or follow-up trigger. New entries land
here as part of the commit that introduces the underlying constraint;
removal is part of the commit that resolves it.

## Recurring

### TTP provider mapping review — quarterly

Re-walk the AbuseIPDB / GreyNoise / abuse.ch ThreatFox / abuse.ch
Feodo Tracker catalogues for new categories or classification changes.
Reconcile against `rules/ttp/R0054..R0058` (the intel-verdict rule
pack) and bump rule versions for any drift. See
`development/TTP_TAGGING.md` §"Hard parts §9 Intel provider drift" for
the operational runbook.

Owner: TTP rule maintainer (currently ANTI).
Cadence: every quarter, first week of the month.
Trigger: rule YAML `next_review` markers (canonical), with a
calendar reminder as backup.

Last reviewed: **2026-05-02** (ship-time audit — see
`development/TTP_TAGGING.md` §9 "Ship-time audit log"; corrected
two AbuseIPDB code typos, expanded the R0054/R0055/R0057 emits
lists to cover the full predicate technique universe, repointed
ThreatFox dispatch from `ioc_type` to `threat_type`, wired the
`AttackerIntel.{abuseipdb_categories, greynoise_tags,
greynoise_name, feodo_malware_family, threatfox_*_types,
threatfox_malware_families}` columns + producer parsing).
Next review: **2026-08-02**.

## One-shot

### TTP Sigma adapter — post-v1

The Sigma rule format adapter is deferred to post-v1 per
`development/TTP_TAGGING.md` §"Tagging engines, layered §5". Lands
once v0 ships and the rule-precision targets stabilize so we have a
calibration reference for translated rules. Until then,
`decnet/ttp/impl/` does not gain a Sigma engine and `rules/ttp/`
stays YAML-only.

Trigger: v0 precision targets met + at least one downstream user
who needs it.

### `attacker.email.received` producer — PAID 2026-05-02

Originally deferred under the premise that "the honeypot SMTP-relay
path does not persist received emails to a DB table." That was wrong
— SMTPProtocol persists every received message as a Bounty artifact
(`bounty_type="artifact"`, `payload.kind="mail"`) at
`decnet/web/ingester.py:596–615`, and the `_summarize_message` helper
already extracts the headers + per-attachment metadata.

The producer was wired in the same commit that struck this entry.
The TTP worker subscribes to `email.received` (per
`decnet/ttp/worker.py:66`) and dispatches to the EmailLifter
(R0041–R0048). After paydown the channel is live for R0041 /
R0043 / R0044 / R0045, and partial for R0046 (extension lane only).

The remaining R0042 / R0046-deep / R0047 / R0048 lanes ride on the
heavyweight extraction follow-up below.

### EmailLifter heavyweight feature extraction — R0042 / R0046 / R0047 / R0048

The cheap header / domain / extension extractions landed with the
2026-05-02 producer paydown above. These predicates still need
deeper signal before they fire:

- **R0042 (mass phish)** — needs `body_simhash`. A near-duplicate
  hash (simhash / minhash) over the body lets the lifter score
  "same template fanned out to many recipients." The extractor is
  decky-side; the wire field is a single string.
- **R0046 (malicious attachment)** — extension lane fires today.
  The remaining lanes need:
  - `attachment_macros: bool` — Office macro detection (oletools or
    a minimal VBA-stream sniff inside the .ole / .docx zip).
  - `attachment_password_protected: bool` — encrypted-archive
    detection across .zip / .7z / .rar.
  - `html_smuggling: bool` — heuristic over HTML body parts looking
    for the canonical `<a download>` + base64-blob / Blob() pattern.
  - `mal_hash_match: bool` — match against a curated bad-hash feed
    (provider TBD; could ride on the same enrich worker as
    AttackerIntel).
- **R0047 (BEC) / R0048 (encoded payload)** — both predicates read
  `body_text`. We deliberately do NOT ship raw body text on the bus
  today: PII concerns, payload size, and the EmailLifter's evidence
  filter strips it anyway. The wire-up needs either (a) a hashed /
  truncated body projection, (b) the lifter reaching back to fetch
  the .eml off disk on the same host, or (c) a privacy-safe
  intermediate (BEC-keyword presence flags, base64 byte counts)
  that satisfies the predicates without leaking raw text. Pick one
  before the extractor work.

Field map per rule: `development/TTP_TAGGING.md` §"Bus topics →
Producer wiring" + `decnet/ttp/impl/email_lifter.py` predicates.

Trigger: any of these rules generates enough signal in production
to justify the extractor cost, OR a bad-hash feed becomes available
and unblocks R0046's mal_hash_match lane in particular.
Owner: TBD.
Filed: 2026-05-02 alongside the DEBT #3 paydown.
