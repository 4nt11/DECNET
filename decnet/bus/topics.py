"""Canonical topic hierarchy for the DECNET ServiceBus.

Locked early so consumers can subscribe with stable wildcard patterns.
Adding new topic families is fine; **renaming** existing ones is a breaking
change for every subscriber and requires a coordinated rollout.

Token structure (NATS-style, dot-separated):

    topology.{topology_id}.mutation.{state}
    topology.{topology_id}.status
    decky.{decky_id}.state
    decky.{decky_id}.traffic
    orchestrator.traffic.{decky_id}
    orchestrator.file.{decky_id}
    orchestrator.email.{decky_id}
    attacker.observed
    attacker.scored
    attacker.session.started
    attacker.session.ended
    attacker.observation.{primitive}
    identity.formed
    identity.observation.linked
    identity.merged
    identity.unmerged
    identity.campaign.assigned
    campaign.formed
    campaign.identity.assigned
    campaign.merged
    campaign.unmerged
    credential.captured
    credential.reuse.detected
    attribution.profile.state_changed
    attribution.profile.multi_actor_suspected
    canary.{token_id}.triggered
    canary.{token_id}.placed
    canary.{token_id}.revoked
    system.log
    system.bus.health
    system.{worker}.health
    email.received
    ttp.tagged
    ttp.rule.fired.{technique_id}
    ttp.rule.suppressed

Wildcards (per :func:`decnet.bus.base.matches`):

* ``*`` matches exactly one token.
* ``>`` matches one-or-more trailing tokens (so ``topology.>`` matches
  ``topology.abc.status`` but not the bare root ``topology``).
"""
from __future__ import annotations

# ─── Root prefixes ───────────────────────────────────────────────────────────

TOPOLOGY = "topology"
DECKY = "decky"
ATTACKER = "attacker"
IDENTITY = "identity"
CAMPAIGN = "campaign"
SYSTEM = "system"
CREDENTIAL = "credential"
ATTRIBUTION = "attribution"
ORCHESTRATOR = "orchestrator"
CANARY = "canary"
SMTP = "smtp"
EMAIL = "email"
TTP = "ttp"


# ─── Leaf event-type constants (the last segment of each topic) ──────────────

# Topology mutation lifecycle states — keep in sync with TopologyMutation.state
# in decnet/web/db/models.py; the bus topic mirrors the DB state machine.
MUTATION_ENQUEUED = "enqueued"
MUTATION_APPLYING = "applying"
MUTATION_APPLIED = "applied"
MUTATION_FAILED = "failed"

# Topology-level status transitions (topology.{id}.status): fires when the
# topology row's status column changes (pending/deploying/active/degraded/failed).
TOPOLOGY_STATUS = "status"

# Decky-level event types (second token).
DECKY_STATE = "state"
DECKY_TRAFFIC = "traffic"
# On-demand mutation request — published by the API/CLI/UI, consumed by
# the mutator's watch loop to force an immediate mutation of one decky
# without waiting for its scheduled interval.  Underscored (not dotted)
# to stay a single NATS token so the builder's validator accepts it.
DECKY_MUTATE_REQUEST = "mutate_request"
# Mutation transition event — distinct from DECKY_STATE ("current
# shape") because a mutation is a *transition* that carries old/new
# services + trigger + timing.  Correlator consumes these (via the
# syslog sidechannel too) to interleave substrate-change markers into
# attacker traversals.
DECKY_MUTATION = "mutation"
# Per-service add/remove on a deployed decky (live; no full redeploy).
# Payload carries ``decky_name``, ``service_name``, optional
# ``topology_id``, and ``services`` (the post-mutation list).  Consumers
# that watch substrate shape (correlator, dashboard, profiler) reconcile
# off these without waiting for the next decnet-state.json snapshot.
DECKY_SERVICE_ADDED = "service_added"
DECKY_SERVICE_REMOVED = "service_removed"
# Per-service config change (the schema-driven Inspector form).  Payload
# carries ``decky_name``, ``service_name``, optional ``topology_id``,
# ``service_config`` (the new validated dict), and ``recreated`` — true
# when the operator hit Apply (container was force-recreated to pick up
# the new env), false when they only hit Save (DB-only).
DECKY_SERVICE_CONFIG_CHANGED = "service_config_changed"
# Async deploy/mutate operation transitions
# (pending/running/succeeded/failed).  Payload: {lifecycle_id, operation,
# status, error?}.  UI polling endpoint is the source of truth; this
# fires for live subscribers (dashboard, mutator-side audit, etc).
DECKY_LIFECYCLE = "lifecycle"

# Attacker event types (second token under the ``attacker`` root).  First
# sighting, session boundary transitions, and score-threshold crossings
# published by correlator + profiler.  Consumers typically subscribe to
# the wildcard ``attacker.>``.
ATTACKER_OBSERVED = "observed"
ATTACKER_SCORED = "scored"
# Published once per successful active probe result (JARM/HASSH/TCPfp/ipv6_leak).
# Distinct from ``observed`` which is the correlator's first-sight signal —
# a fingerprint is additional evidence about an already-observed attacker.
# Known payload ``kind`` discriminators carried in this topic:
#   "jarm"         — JARM TLS server hash (prober)
#   "hassh"        — HASSHServer SSH key-exchange hash (prober)
#   "tcpfp"        — TCP/IP stack fingerprint hash (prober)
#   "tls_cert"     — leaf TLS certificate SHA-256 (prober)
#   "ipv6_leak"    — fe80:: link-local address observed via passive sniffer
#                    or active ICMPv6 solicitation (prober + sniffer);
#                    payload: {attacker_ip, addr, iid_kind, mac_oui, vector,
#                              on_iface, observed_at}
ATTACKER_FINGERPRINTED = "fingerprinted"
# Published when the prober observes a NEW hash for an
# (attacker_ip, port, probe_type) triple it has seen before — i.e. the
# attacker rotated their VPS, rebuilt their SSH server, swapped their
# TLS cert.  Distinct from ``fingerprinted`` which fires on every probe
# result; ``fingerprint_rotated`` fires only on diff and carries both
# old_hash + new_hash.  Producer: prober (via the rotation library);
# consumers: dashboard, forensics, attribution clustering.
ATTACKER_FINGERPRINT_ROTATED = "fingerprint_rotated"
ATTACKER_SESSION_STARTED = "session.started"
ATTACKER_SESSION_ENDED = "session.ended"
# Published by the ``decnet enrich`` worker after an enrichment pass
# succeeds for an attacker IP (one or more 3rd-party intel providers
# returned a verdict).  Payload carries the aggregate verdict + per-
# provider summary so SIEM-bound webhooks don't need to re-query the DB.
ATTACKER_INTEL_ENRICHED = "intel.enriched"
# Per-primitive BEHAVE-SHELL observation. Full topic shape:
#   attacker.observation.<primitive>
# e.g. ``attacker.observation.motor.input_modality``.  Producer:
# ``decnet/profiler/behave_shell/`` (extractor library called from the
# profiler worker on ``attacker.session.ended``); consumers: dashboard
# SSE relay, attribution engine state machine, federation gossip
# (post-v0).  See development/BEHAVE-INTEGRATION.md §"Bus topics" for
# the wire-format contract — the prefix is documentation + pattern
# match only; bus auth is socket file perms (DEBT-029 §2), not
# topic-level.  The ``primitive`` segment MAY contain dots
# (``motor.shell_mastery.tab_completion``) — the same dotted-leaf
# rule that ``attacker.session.ended`` uses.
ATTACKER_OBSERVATION_PREFIX = "observation"

# Identity-resolution event types (second/third tokens under ``identity``).
# Published by the (future) clusterer worker — see
# development/IDENTITY_RESOLUTION.md.  Constants ship in this commit;
# no publishers exist yet, but consumers (webhook worker, dashboard
# SSE relay) can subscribe to ``identity.>`` from day one and receive
# events the instant the clusterer comes online.
#
#   identity.formed              — clusterer creates a new identity from
#                                  one or more observations
#   identity.observation.linked  — observation attached to an existing
#                                  identity (or reattached from another)
#   identity.merged              — two identities collapsed; loser gets
#                                  ``merged_into_uuid`` set, subscribers
#                                  re-key cached references to the winner
#   identity.unmerged            — revocable-merge undo: contradicting
#                                  evidence cleared ``merged_into_uuid``
#                                  and re-split observations.  The
#                                  resurrected side's UUID is the same
#                                  as the prior loser, so subscribers
#                                  that cached references to the loser
#                                  during the merged interval can
#                                  re-attach without a new lookup.
#
# ``identity.campaign.assigned`` is deferred; it ships when the campaign
# clusterer ships.  YAGNI before then.
IDENTITY_FORMED = "formed"
IDENTITY_OBSERVATION_LINKED = "observation.linked"
IDENTITY_MERGED = "merged"
IDENTITY_UNMERGED = "unmerged"
# Campaign-clusterer cross-family event — fires under ``identity.>`` so
# identity-stream subscribers (e.g. the IdentityDetail SSE client) get
# notified the moment an identity's ``campaign_id`` changes without
# having to subscribe to the campaign topic family.  The same event
# fires under ``campaign.identity.assigned`` for campaign-side
# subscribers.
IDENTITY_CAMPAIGN_ASSIGNED = "campaign.assigned"

# Campaign-clusterer event types (second/third tokens under
# ``campaign``).  Mirror of the identity family at the layer above:
# campaigns group identities into operations, and the clusterer
# publishes the same form / link / merge / unmerge lifecycle.
#
#   campaign.formed              — clusterer creates a new campaign from
#                                  one or more identities
#   campaign.identity.assigned   — identity attached to an existing
#                                  campaign (or reassigned from another)
#   campaign.merged              — two campaigns collapsed; loser gets
#                                  ``merged_into_uuid`` set, subscribers
#                                  re-key cached references to the winner
#   campaign.unmerged            — revocable-merge undo: contradicting
#                                  evidence cleared ``merged_into_uuid``
#                                  and re-split identities
CAMPAIGN_FORMED = "formed"
CAMPAIGN_IDENTITY_ASSIGNED = "identity.assigned"
CAMPAIGN_MERGED = "merged"
CAMPAIGN_UNMERGED = "unmerged"

# Credential event types (second/third tokens under ``credential``).
# ``credential.captured`` fires once per upserted Credential row — the
# correlator listens for it and runs the cred-reuse query in response,
# so reuse detection latency is sub-second after a fresh capture.
# ``credential.reuse.detected`` fires when the correlator inserts a new
# CredentialReuse row or grows an existing one (added decky/service/IP).
CREDENTIAL_CAPTURED = "captured"
CREDENTIAL_REUSE_DETECTED = "reuse.detected"

# Attribution-engine event types (second/third tokens under
# ``attribution``).  Published by the v0 attribution worker
# (``decnet.correlation.attribution_worker``) which subscribes to
# ``attacker.observation.>`` and runs the per-(identity, primitive)
# state machine.  See ``development/ATTRIBUTION-ENGINE.md``.
#
#   attribution.profile.state_changed         — per-primitive state
#                                               transition (e.g.
#                                               stable → drifting).
#                                               Payload: identity_uuid,
#                                               primitive, old_state,
#                                               new_state, current_value,
#                                               confidence,
#                                               observation_count, ts.
#   attribution.profile.multi_actor_suspected — fires when ≥ 2
#                                               primitives flag the same
#                                               identity as multi_actor
#                                               concurrently. Cross-
#                                               primitive correlator;
#                                               single-primitive
#                                               multi_actor is too noisy
#                                               on its own. Payload:
#                                               identity_uuid, primitives,
#                                               evidence_summary,
#                                               confidence, ts.
#
# These are *derived* signals — distinct from
# ``identity.*`` (clusterer lifecycle, IDENTITY_RESOLUTION.md) and
# ``attacker.observation.*`` (raw extractor envelopes,
# BEHAVE-INTEGRATION.md). The three families compose: observations feed
# the attribution engine, the engine emits derived state, the clusterer
# reads observations + state to form / merge identities.
ATTRIBUTION_PROFILE_PREFIX = "profile"
ATTRIBUTION_PROFILE_STATE_CHANGED = "profile.state_changed"
ATTRIBUTION_PROFILE_MULTI_ACTOR_SUSPECTED = "profile.multi_actor_suspected"

# Canary-token event types (third token under ``canary``).
#
#   canary.{token_id}.placed     — orchestrator/API successfully planted a
#                                  canary artifact inside a decky's
#                                  filesystem (or persisted a passive token
#                                  that has no callback wiring).  Lets
#                                  dashboards reflect baseline coverage in
#                                  real time without a DB poll.
#   canary.{token_id}.triggered  — ``decnet canary`` worker observed a
#                                  callback hit (HTTP slug or DNS subdomain
#                                  lookup) for the token.  Payload carries
#                                  ``src_ip``, ``user_agent``, ``request_path``
#                                  and any DNS qname so downstream
#                                  consumers (correlator, webhook fanout)
#                                  can attribute and forward without a
#                                  follow-up DB read.
#   canary.{token_id}.revoked    — operator removed a token; planter unlinked
#                                  the file (best-effort) and the row was
#                                  marked ``revoked``.  Subscribers may
#                                  evict cached lookups by token id.
CANARY_PLACED = "placed"
CANARY_TRIGGERED = "triggered"
CANARY_REVOKED = "revoked"

# Orchestrator event types (second token under ``orchestrator``).  The
# orchestrator worker publishes one of these per synthetic action it
# drives against a decky — cheap inter-decky traffic and filesystem
# mutations whose role is to keep the honeypot from looking suspiciously
# static.  Always nested with the destination decky uuid as the third
# token, so consumers can subscribe to a single decky's life-injection
# stream via ``orchestrator.*.<decky_uuid>``.
ORCHESTRATOR_TRAFFIC = "traffic"
ORCHESTRATOR_FILE = "file"
# Emailgen — published by the ``decnet emailgen`` worker once per generated
# fake email delivered into a mail decky's maildir.  Third token is the
# destination mail-decky uuid (the IMAP/POP3 host serving the mailbox),
# matching the ``orchestrator.*.<decky_uuid>`` subscription pattern.
ORCHESTRATOR_EMAIL = "email"

# System event types.
SYSTEM_LOG = "log"
SYSTEM_BUS_HEALTH = "bus.health"
# Worker-health leaf — built per-worker as ``system.<worker>.health`` via
# :func:`system_health`.  The leaf constant stays the same across workers;
# the worker name goes in the middle token.
SYSTEM_HEALTH = "health"
# Worker-control leaf — built per-worker as ``system.<worker>.control`` via
# :func:`system_control`.  Admin-originated stop intents travel on this
# topic; each worker subscribes to its own.
SYSTEM_CONTROL = "control"

# Control payload ``action`` values — the wire vocabulary.  Only ``stop`` is
# handled in v1; ``start`` is reserved because a stopped worker has no
# subscriber, so starting requires external supervision (systemd).
WORKER_CONTROL_STOP = "stop"
WORKER_CONTROL_START = "start"

# Webhook subscription-set changed — published by the CRUD router after any
# create / update / delete on WebhookSubscription so the webhook worker can
# reload its in-memory subscription list and re-subscribe to the new union
# of patterns. Payload is currently empty; consumers only need the signal.
WEBHOOK_SUBSCRIPTIONS_CHANGED = "system.webhook.subscriptions_changed"

# Email-receipt event — fired by smtp / smtp-relay services on full-message
# receipt (envelope + headers + body + attachments captured). Single-token
# leaf so the bus tokenizer accepts it directly under the ``email`` root.
# Consumed by the TTP ``email_lifter`` for header / body-pattern / attachment
# rules. PII rule (TTP_TAGGING.md "Hard parts §6"): payload carries hashes,
# counts, header names, and rcpt-domain sets — never rcpt addresses or body
# bytes.
EMAIL_RECEIVED = "received"

# TTP-tagging event types (second/third tokens under ``ttp``).
#
#   ttp.tagged                     — one or more new tags written. Published
#                                    only when ``INSERT OR IGNORE`` wrote at
#                                    least one new row; idempotent
#                                    re-evaluations publish nothing
#                                    (loop-prevention invariant — see
#                                    TTP_TAGGING.md).
#   ttp.rule.fired.{technique_id}  — per-technique fan-out for SIEM
#                                    consumers that subscribe to a single
#                                    technique. Topic key is the parent
#                                    technique; sub_technique is in the
#                                    payload. Built via :func:`ttp_rule_fired`.
#   ttp.rule.suppressed            — rule fired but the tag was dropped
#                                    (confidence below floor, rate-limited,
#                                    or the rule's RuleState was disabled).
#                                    Observability signal for the dashboard.
#
# Per-rule reload + state-change topics. Built via
# :func:`ttp_rule_reloaded` / :func:`ttp_rule_state`; SIEM consumers
# subscribe to ``ttp.rule.reloaded.>`` (every rule) or
# ``ttp.rule.reloaded.R0001`` (one rule) at their preferred granularity.
TTP_TAGGED = "tagged"
TTP_RULE_FIRED = "rule.fired"
TTP_RULE_SUPPRESSED = "rule.suppressed"
TTP_RULE_RELOADED = "rule.reloaded"
TTP_RULE_STATE = "rule.state"


# ─── Builders ────────────────────────────────────────────────────────────────

def topology_mutation(topology_id: str, state: str) -> str:
    """Build ``topology.<id>.mutation.<state>``.

    *state* should be one of the ``MUTATION_*`` constants.
    """
    _reject_tokens(topology_id, state)
    return f"{TOPOLOGY}.{topology_id}.mutation.{state}"


def topology_status(topology_id: str) -> str:
    """Build ``topology.<id>.status``."""
    _reject_tokens(topology_id)
    return f"{TOPOLOGY}.{topology_id}.{TOPOLOGY_STATUS}"


def decky(decky_id: str, event_type: str) -> str:
    """Build ``decky.<id>.<event_type>``.

    *event_type* is typically one of ``DECKY_STATE`` or ``DECKY_TRAFFIC``.
    """
    _reject_tokens(decky_id, event_type)
    return f"{DECKY}.{decky_id}.{event_type}"


def decky_mutation(decky_id: str) -> str:
    """Build ``decky.<id>.mutation``."""
    _reject_tokens(decky_id)
    return f"{DECKY}.{decky_id}.{DECKY_MUTATION}"


def decky_lifecycle(decky_id: str) -> str:
    """Build ``decky.<id>.lifecycle``."""
    _reject_tokens(decky_id)
    return f"{DECKY}.{decky_id}.{DECKY_LIFECYCLE}"


def system(event_type: str) -> str:
    """Build ``system.<event_type>``.

    *event_type* may itself contain dots (e.g. ``bus.health``) — we don't
    re-validate the already-constant leaves; this just prefixes.
    """
    if not event_type:
        raise ValueError("system topic requires a non-empty event_type")
    return f"{SYSTEM}.{event_type}"


def credential(event_type: str) -> str:
    """Build ``credential.<event_type>``.

    *event_type* is typically one of :data:`CREDENTIAL_CAPTURED` or
    :data:`CREDENTIAL_REUSE_DETECTED`. Dotted leaves
    (``reuse.detected``) are permitted — same rationale as
    :func:`system`.
    """
    if not event_type:
        raise ValueError("credential topic requires a non-empty event_type")
    return f"{CREDENTIAL}.{event_type}"


def attacker(event_type: str) -> str:
    """Build ``attacker.<event_type>``.

    *event_type* is typically one of ``ATTACKER_OBSERVED``,
    ``ATTACKER_SCORED``, ``ATTACKER_SESSION_STARTED``,
    ``ATTACKER_SESSION_ENDED``.  Dotted leaves (``session.started``) are
    permitted — same rationale as :func:`system`.
    """
    if not event_type:
        raise ValueError("attacker topic requires a non-empty event_type")
    return f"{ATTACKER}.{event_type}"


def attacker_observation(primitive: str) -> str:
    """Build ``attacker.observation.<primitive>``.

    *primitive* is the fully-qualified BEHAVE-SHELL primitive path
    (e.g. ``motor.input_modality``,
    ``cognitive.feedback_loop_engagement``,
    ``motor.shell_mastery.tab_completion``).  Dotted primitives are
    permitted — this matches the format
    ``behave_shell.spec.event_adapter.event_topic_for`` produces
    upstream, and DECNET's bus admits the dotted leaf the same way
    :func:`attacker` does for ``session.started``.

    Empty string is rejected so a downstream typo doesn't ship as
    ``attacker.observation.``.
    """
    if not primitive:
        raise ValueError(
            "attacker_observation topic requires a non-empty primitive",
        )
    return f"{ATTACKER}.{ATTACKER_OBSERVATION_PREFIX}.{primitive}"


def attribution(event_type: str) -> str:
    """Build ``attribution.<event_type>``.

    *event_type* is typically one of
    :data:`ATTRIBUTION_PROFILE_STATE_CHANGED` or
    :data:`ATTRIBUTION_PROFILE_MULTI_ACTOR_SUSPECTED` — both contain a
    dot (``profile.state_changed``) which is permitted under the same
    "trailing dotted leaf" rule that ``attacker.session.started`` uses.
    """
    if not event_type:
        raise ValueError("attribution topic requires a non-empty event_type")
    return f"{ATTRIBUTION}.{event_type}"


def campaign(event_type: str) -> str:
    """Build ``campaign.<event_type>``.

    *event_type* is typically one of :data:`CAMPAIGN_FORMED`,
    :data:`CAMPAIGN_IDENTITY_ASSIGNED`, :data:`CAMPAIGN_MERGED`, or
    :data:`CAMPAIGN_UNMERGED`. Dotted leaves (``identity.assigned``)
    are permitted — same rationale as :func:`system`.
    """
    if not event_type:
        raise ValueError("campaign topic requires a non-empty event_type")
    return f"{CAMPAIGN}.{event_type}"


def identity(event_type: str) -> str:
    """Build ``identity.<event_type>``.

    *event_type* is typically one of :data:`IDENTITY_FORMED`,
    :data:`IDENTITY_OBSERVATION_LINKED`, :data:`IDENTITY_MERGED`, or
    :data:`IDENTITY_UNMERGED`. Dotted leaves (``observation.linked``)
    are permitted — same rationale as :func:`system`.
    """
    if not event_type:
        raise ValueError("identity topic requires a non-empty event_type")
    return f"{IDENTITY}.{event_type}"


def orchestrator(event_type: str, decky_id: str) -> str:
    """Build ``orchestrator.<event_type>.<decky_id>``.

    *event_type* should be one of :data:`ORCHESTRATOR_TRAFFIC` or
    :data:`ORCHESTRATOR_FILE`. The destination decky is always the
    third token so per-decky subscribers can use
    ``orchestrator.*.<decky_uuid>``.
    """
    _reject_tokens(event_type, decky_id)
    return f"{ORCHESTRATOR}.{event_type}.{decky_id}"


def canary(token_id: str, event_type: str) -> str:
    """Build ``canary.<token_id>.<event_type>``.

    *event_type* should be one of :data:`CANARY_PLACED`,
    :data:`CANARY_TRIGGERED`, or :data:`CANARY_REVOKED`.  The token id
    is always the second token so per-token subscribers can use
    ``canary.<token_id>.>`` and fleet-wide consumers (webhook fanout,
    correlator) use ``canary.>``.
    """
    _reject_tokens(token_id, event_type)
    return f"{CANARY}.{token_id}.{event_type}"


def system_health(worker: str) -> str:
    """Build ``system.<worker>.health``.

    Worker-health heartbeats live as a nested leaf under ``system`` so
    consumers can subscribe to ``system.*.health`` for every worker at
    once, or to ``system.mutator.health`` for a single one.  *worker* is
    validated as a regular segment — no dots, wildcards, or whitespace.
    """
    _reject_tokens(worker)
    return f"{SYSTEM}.{worker}.{SYSTEM_HEALTH}"


def system_control(worker: str) -> str:
    """Build ``system.<worker>.control``.

    Admin-originated stop (and, eventually, start) intents are published
    here; the worker in question subscribes to its own address and reacts.
    Payload shape::

        {"action": "stop", "requested_by": "<username>", "ts": <unix>}

    *action* must be one of :data:`WORKER_CONTROL_STOP` /
    :data:`WORKER_CONTROL_START`; any other value is ignored by the
    listener.  Same segment rules as :func:`system_health`.
    """
    _reject_tokens(worker)
    return f"{SYSTEM}.{worker}.{SYSTEM_CONTROL}"


def smtp(event_type: str) -> str:
    """Build ``smtp.<event_type>``.

    *event_type* may contain dots (e.g. ``probe.pending``).
    """
    if not event_type:
        raise ValueError("smtp topic requires a non-empty event_type")
    return f"{SMTP}.{event_type}"


def email_topic(event_type: str) -> str:
    """Build ``email.<event_type>``.

    Named ``email_topic`` rather than ``email`` to avoid shadowing the
    Python ``email`` stdlib package at import sites that pull both.
    *event_type* is typically :data:`EMAIL_RECEIVED`.
    """
    if not event_type:
        raise ValueError("email topic requires a non-empty event_type")
    return f"{EMAIL}.{event_type}"


def ttp(event_type: str) -> str:
    """Build ``ttp.<event_type>``.

    *event_type* is typically one of :data:`TTP_TAGGED`,
    :data:`TTP_RULE_FIRED`, or :data:`TTP_RULE_SUPPRESSED`. Dotted
    leaves (``rule.fired``) are permitted — same rationale as
    :func:`system`. For per-technique fan-out use
    :func:`ttp_rule_fired`.
    """
    if not event_type:
        raise ValueError("ttp topic requires a non-empty event_type")
    return f"{TTP}.{event_type}"


def ttp_rule_fired(technique_id: str) -> str:
    """Build ``ttp.rule.fired.<technique_id>``.

    Per-technique fan-out: SIEM subscribers can listen on
    ``ttp.rule.fired.>`` for everything, ``ttp.rule.fired.T1110`` for
    one technique. *technique_id* is validated as a single segment —
    sub-techniques like ``T1110.001`` are rejected because they would
    split into two tokens. The topic key is the parent technique;
    ``sub_technique_id`` lives in the payload.
    """
    _reject_tokens(technique_id)
    return f"{TTP}.rule.fired.{technique_id}"


def ttp_rule_reloaded(rule_id: str) -> str:
    """Build ``ttp.rule.reloaded.<rule_id>``.

    Per-rule fan-out fired by the :class:`~decnet.ttp.store.base.RuleStore`
    when a rule's *definition* changes (YAML edit on the filesystem
    backend, ``ttp_rule`` row update on the database backend). One event
    per per-rule edit — never batched (the "incremental, never batched"
    property in TTP_TAGGING.md §"Bus topics" inherits its granularity
    from :meth:`RuleStore.subscribe_changes`).

    Subscribers: ``ttp.rule.reloaded.>`` for every rule,
    ``ttp.rule.reloaded.R0001`` for one. *rule_id* is validated as a
    single segment.
    """
    _reject_tokens(rule_id)
    return f"{TTP}.{TTP_RULE_RELOADED}.{rule_id}"


def ttp_rule_state(rule_id: str) -> str:
    """Build ``ttp.rule.state.<rule_id>``.

    Per-rule fan-out fired by the :class:`~decnet.ttp.store.base.RuleStore`
    when a rule's *operational state* changes (operator hits the disable
    button, an ``expires_at`` TTL fires and auto-reverts the state).
    *rule_id* is validated as a single segment.
    """
    _reject_tokens(rule_id)
    return f"{TTP}.{TTP_RULE_STATE}.{rule_id}"


def _reject_tokens(*parts: str) -> None:
    """Reject topic segments that would break NATS-style tokenization.

    Dots, wildcards, whitespace, and empty strings in a *segment* would
    silently corrupt the hierarchy (e.g. ``topology.a.b.status`` for a
    ``topology_id`` of ``"a.b"``).  Raise early at the builder instead of
    shipping a malformed topic to the wire.
    """
    for p in parts:
        if not p:
            raise ValueError("topic segment must not be empty")
        if "." in p or "*" in p or ">" in p or any(c.isspace() for c in p):
            raise ValueError(
                f"topic segment {p!r} may not contain '.', '*', '>', or whitespace"
            )
