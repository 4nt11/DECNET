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
the operational rationale.

Owner: TTP rule maintainer (currently ANTI).
Cadence: every quarter, first week of the month.
Trigger: calendar reminder; no automated probe today.

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
