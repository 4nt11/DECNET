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

### `attacker.email.received` producer — wire when SMTP-receive
### persistence lands

The TTP worker subscribes to `email.received` for the EmailLifter
(R0041–R0048), but no upstream component publishes the topic today.
The honeypot SMTP-relay path (`decnet/services/smtp_relay.py`) does
not persist received emails to a DB table the way ingester /
collector persist log events, so there is no source row to fan out
on. See `development/TTP_TAGGING.md` §"Bus topics → Producer
wiring" for the full producer audit.

**STALE PREMISE (2026-05-02):** ANTI noted during the intel audit
that the SMTP honeypots DO persist all received messages today.
Re-triage this entry — the gating premise above may no longer
hold and the producer wiring may be paydown-able directly. Map
the actual SMTP-receive persistence to `ReceivedEmail` (or its
extant analogue), then wire the publisher.

Trigger: SMTP-receive persistence model lands (a `ReceivedEmail`
SQLModel + ingest path). Wire the publisher in the same PR.
Owner: TBD.
