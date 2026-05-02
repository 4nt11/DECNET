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

### EmailLifter heavyweight feature extraction — PARTIAL PAID 2026-05-02

The Layer-2 extractors for R0042 / R0046 (macro / password /
smuggling lanes) / R0048 landed in commits `291b78c1` (decky
`_summarize_message` extension) and the follow-up ingester producer
projection. After paydown the bus payload carries:

- `body_simhash` — inlined 64-bit Charikar simhash for R0042
- `body_base64_bytes` — largest decoded base64 chunk size for R0048
- `attachment_macros` — OOXML `vbaProject.bin` sniff for R0046
- `attachment_password_protected` — ZIP encryption flag + 7z / RAR
  / CFBF magic-byte match for R0046
- `html_smuggling` — lxml structural parse (with regex fallback) for
  R0046's HTML-smuggling lane

R0042 / R0046 (three lanes) / R0048 fire end-to-end after the
2026-05-02 paydown. The remaining lanes are split into two narrower
follow-up entries below: `R0046 mal_hash_match` (needs a curated
bad-hash feed — feed integration, not extraction) and `R0047 BEC`
(needs body_text on the wire, blocked on the agent UID/GID DEBT
entry that gates artifact disk-reach).

### EmailLifter mal-hash feed integration — R0046 mal_hash_match

R0046's `mal_hash_match` lane stays gated until DECNET has a
curated bad-hash feed it can lookup attachment SHA-256s against.
Until then the producer ships
`attachment_sha256s: list[str]` on the bus (already does as of the
2026-05-02 paydown) but no producer or worker resolves a
`mal_hash_match: bool` against a feed.

Design sketch (mirrors the Feodo bulk-feed pattern at
`decnet/intel/feodo.py`):

- **Feed source**: MalwareBazaar's public SHA-256 dump as the v0
  candidate (free, daily refresh, ~100 MB compressed). Operators
  with paid VT subscriptions can swap the provider behind the same
  factory.
- **Storage**: in-memory set keyed by sha256, TTL-cached on a slow
  refresh loop. Mirror `FeodoProvider`'s `_ensure_fresh` /
  `_refresh` shape exactly — the same trade-offs apply (free at
  call-site, one network round-trip per refresh window).
- **Wiring**: ingester reads each `attachment_sha256` in the
  manifest at `_publish_email_received` time, checks against the
  cached feed, sets `mal_hash_match: bool` on the bus payload.
- **Rule pack**: no rule changes. `_p_malicious_attachment` already
  reads `payload.get("mal_hash_match")` — silent today because the
  field is absent.

Trigger: a curated feed source is selected (MalwareBazaar dump or
better) and the operator has bandwidth / disk for a fresh refresh
loop.
Owner: TBD.
Filed: 2026-05-02 alongside the heavyweight paydown.

### EmailLifter R0047 BEC — unblock when artifact disk-reach lands

R0047's predicate (`_p_bec` at
`decnet/ttp/impl/email_lifter.py:244`) reads `body_text` and
`subject`, substring-matching them against per-rule keyword lists.
Shipping raw body text on the abstracted service bus is the wrong
privacy stance — the bus transport is abstracted (the UNIX-socket
implementation today may swap to a networked transport tomorrow),
and treating "loopback today" as a license to ship PII would bite
the moment that swap happens.

The right solution is **disk-reach**: the EmailLifter on tag-time
opens the `.eml` from the artifact tree at
`/var/lib/decnet/artifacts/{decky}/smtp/{stored_as}` and runs the
predicate against the body parsed in-process. Bus carries only the
artifact pointer; raw body text never leaves the host disk
boundary.

This is currently **blocked** by an unresolved UID/GID DEBT entry
— `decnet ttp` will run on agents but cannot read artifact files
written by the SMTP decky even on the same host because of the
permission mismatch. R0047 stays gated until that resolves; the
legacy `_p_bec` body_text path remains in place untouched, so
when disk-reach lands the predicate works without any code
change.

Trigger: the agent UID/GID DEBT entry is paid, allowing
`decnet ttp` to read artifacts written by deckies. Then add a
disk-reach helper to the EmailLifter that opens the `.eml` lazily
when a body-aware predicate runs.
Owner: TBD.
Cross-reference: this entry is gated on the agent UID/GID DEBT
entry. Resolution of that unblocks R0047 BEC immediately.
Filed: 2026-05-02 alongside the heavyweight paydown.
