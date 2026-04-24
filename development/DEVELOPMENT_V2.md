# DECNET Development Roadmap — V2

Post-v1 direction. Everything here is *after* the v1 box is closed; this
document exists to make sure the schema and architectural decisions we take
*before* v1 ships don't box us out of the interesting post-v1 work.

---

## Keystroke Dynamics & Session Profiling

**Goal:** graduate the Profiler from IP-keyed attribution to
identity-independent correlation using structured per-session feature
vectors. Attackers rotate IPs; they don't rotate their hands.

The sessrec pipeline (v1) already lands every keystroke as a `ch:"i"` event
with a `t` timestamp in the asciinema day-shard. The raw data is sitting
on disk. The work is *not* collection — it's feature extraction, schema,
and correlation primitives.

### Features — cheap, post-processing over existing shards

All of these are derived from a single pass over a session's `"i"` events.
No new capture infra.

- **Inter-keystroke interval (IKI) distribution**
  `kd_iki_mean`, `kd_iki_stdev`, `kd_iki_p50`, `kd_iki_p95`.
  Humans: 80–250ms, high variance. `sshpass`/`paramiko`/`expect`: <5ms,
  near-zero variance. Paste attacks: bimodal (one huge gap, then a burst).
- **Burst ratio**
  `kd_burst_ratio` = fraction of keystrokes within <30ms of the previous
  one. High = pasted commands, low = typed. One number; cleanly separates
  operator-at-keyboard from automation.
- **Control-character mix** (not just backspace — the whole family)
  `kd_ctrl_backspace`, `kd_ctrl_wkill` (`\x17`), `kd_ctrl_ukill` (`\x15`),
  `kd_ctrl_abort` (`\x03`), `kd_ctrl_eof` (`\x04`), `kd_arrow_rate`
  (`\x1b[A/B/C/D`), `kd_tab_rate` (`\x09`).
  *Presence of any control char* → bot/human split. *Mix* →
  tooling/experience fingerprint. Heavy Ctrl-W = experienced Unix user.
  Heavy arrows = history editing. Heavy tab = exploratory recon. Bots
  emit `\r`-terminated literals and nothing else.
- **Prompt-to-enter latency distribution**
  `kd_enter_latency_p50`, `kd_enter_latency_p95`, and crucially the
  **ratio p95/p50** as a cheap tail-heaviness indicator. Shape matters
  more than median. Readers have long right-tails; memorized playbooks
  have tight distributions; bots have cliff-edge distributions at whatever
  `sleep` is hardcoded. p50 alone blurs these together.
- **Typing-to-think ratio**
  `kd_think_ratio` = idle gap (>2s before Enter) / total session time.
  Recon/read behavior vs. memorized execution.
- **Digraph rhythm fingerprint** — `kd_digraph_simhash`, 64-bit.
  **Use SimHash (or MinHash) over quantile-bucketed digraph timings**,
  not a regular hash. Hamming-distance comparable — similar rhythms get
  similar hashes, which is the entire point. A plain hash of quantized
  timings loses this: one digraph off = totally different hash. SimHash
  is ~30 lines. This is the feature that graduates "fingerprint" into
  "identity."

### Schema — the single most important decision on this page

The features above *must* live in a dedicated `session_profile` table,
UUID-keyed, foreign key to the owning `session_recorded` Log row.
**Not** in `meta_json_b64`. **Not** as ad-hoc bounty strings.

Rationale:
- Correlation wants `find_similar_sessions(sid, ε)` — that's a SQL query
  over indexed float columns, not a 50k-row JSON parse.
- Retrofitting is brutal. Decide the shape now, when the table is empty.
- Federation (see below) needs these as structured columns to be
  gossipable without per-operator parsing quirks.

Sketch:

```sql
CREATE TABLE session_profile (
    sid              TEXT PRIMARY KEY,           -- session UUID
    log_id           INTEGER REFERENCES logs(id), -- owning session_recorded
    schema_version   INTEGER NOT NULL,            -- evolve features without breaking gossip
    -- timing moments
    kd_iki_mean              REAL,
    kd_iki_stdev             REAL,
    kd_iki_p50               REAL,
    kd_iki_p95               REAL,
    kd_enter_latency_p50     REAL,
    kd_enter_latency_p95     REAL,
    -- ratios
    kd_burst_ratio           REAL,
    kd_think_ratio           REAL,
    -- control-char rates
    kd_ctrl_backspace        REAL,
    kd_ctrl_wkill            REAL,
    kd_ctrl_ukill            REAL,
    kd_ctrl_abort            REAL,
    kd_ctrl_eof              REAL,
    kd_arrow_rate            REAL,
    kd_tab_rate              REAL,
    -- rhythm fingerprint
    kd_digraph_simhash       BLOB,                -- 8 bytes, Hamming-comparable
    -- derived
    total_keystrokes         INTEGER,
    session_duration_s       REAL,
    created_at               TIMESTAMP
);
CREATE INDEX ix_session_profile_simhash ON session_profile(kd_digraph_simhash);
```

`schema_version` is non-negotiable from day one. Federation gossip in v2
requires cross-operator compatibility; bumping feature definitions without
a version field will silently poison other operators' clustering.

### Sequencing — build the shell before the features

The natural instinct is: features first, then correlation. **Invert it.**

1. **`session_profile` table + empty write path** — one row per session, all
   nulls. Ships immediately.
2. **Correlator `find_similar_sessions(sid, ε)` primitive — stubbed.**
   Returns empty. Wire the API, wire the UI surface in `SessionDrawer`
   ("Similar Sessions: none yet").
3. **First features** — the five cheapest (IKI moments, burst ratio,
   control-char mix). Populate the table.
4. **Similarity function goes live** — Euclidean distance over normalized
   float features, Hamming distance over simhash. No ML needed.
5. **Digraph simhash** — once cheap features are validated as useful.
6. **Correlation graph integration** — `CorrelationEngine` learns to
   follow profile-similarity edges, not just IP edges.

**Why inverted:** once operators see a session profile with no "similar
sessions" surface, they'll ask for it, and the UX (what's shown, how
distance is rendered, what actions the link affords) will drive which
features matter. Build the shell, let demand signal feature priority.

### Correlation — what this enables

Today, `CorrelationEngine` keys on `attacker_ip`. Session profiles let it
graduate to **identity-independent correlation**.

Concrete scenario:
> Attacker hits operator A's maze from IP X. Three weeks later, hits
> operator B's maze from IP Y. IPs don't match. But:
> - `kd_digraph_simhash` Hamming distance: 3
> - HASSH fingerprint: identical
> - JARM: identical
> - Command-sequence 3-gram overlap: 60%
>
> That's a cross-operator identity claim with receipts. SQL query, not
> research project.

Without structured session profiles, that analysis is literally impossible.
With them, it's a join.

### Federation implication (v2/v3)

Session profile vectors are **exactly** the thing to gossip in the
federation layer. They are:
- **Small** — a few floats + an 8-byte hash. Cheap on the wire.
- **Semantically meaningful** — encode identity without encoding
  operator-specific infrastructure or PII.
- **Collision-rich** — similar vectors across operators = shared adversary,
  same pattern as the fingerprint-tuple idea, but richer and noisier-signal.

The `session_profile` schema is effectively the v2 federation wire format.
Design it that way from day one:
- `schema_version` field (mentioned above).
- No operator-identifying fields (decky name, internal IP, host labels).
- SimHash specifically because Hamming distance works across operators
  without needing shared training data.

### Cost estimate

- Five cheap features + table + stubbed `find_similar_sessions`:
  **½ to 1 day** of implementation once the codebase is known.
- Digraph simhash + live similarity: **another 1–2 days**.
- Correlation engine integration: **depends on how deep the graph walk
  goes** — 2–5 days for a first pass.

The expensive part is not implementation. It's **deciding the schema well
enough that we don't regret it in six months.** Hence this document.

### What *not* to build

- **Typing biometric login.** That's the research-paper framing. Wrong
  frame for a honeypot. We're doing *tooling attribution* and *operator
  clustering*, not authentication.
- **Hold time / pressure / velocity.** Not on the SSH wire. Dead-end
  without attacker-side instrumentation they will not run.
- **ML clustering before similarity.** Euclidean + Hamming over normalized
  features handles the first useful year of data. Don't reach for sklearn
  until the simple thing demonstrably fails.

---

## Open questions to resolve before writing code

1. **Normalization strategy for Euclidean distance** — z-score per-feature
   over rolling window? Fixed population stats? Operator-local vs.
   gossip-aligned?
2. **ε tuning** — start empirically. Seed the UI with "show top-N nearest"
   rather than a distance threshold. Learn ε from operator feedback.
3. **Retention** — session profiles are small; keep indefinitely? Or
   co-expire with the owning log row?
4. **Privacy boundary on gossip** — do we hash the sid on the wire, or
   exchange it plaintext? First pass: hashed, with a challenge-response
   if two operators want to confirm same-session.

---

## Federation

**Goal:** cross-operator threat-intel sharing. An operator in country A
observes an attacker, and an operator in country B benefits — without
either operator leaking internal infrastructure, attracting legal
exposure, or becoming part of the other's attack surface.

### Framing — federation, not P2P

"Federation API + P2P" is two contradictory models. Pick **federation
(Mastodon/ActivityPub shape), not P2P.** Reasons:

- Operators already run persistent, addressable infrastructure. There is
  a DECNET master host with a stable identity. That's a server, not a
  transient peer. The hard problem libp2p/Nostr exist to solve is already
  solved here.
- Threat-intel sharing is fundamentally **many-to-many gossip with audit
  trails**, not many-to-many streaming. Federated server-to-server gossip
  maps naturally; DHT/P2P overhead buys nothing.
- SWARM already ships mTLS + per-host cert fingerprint pinning. Promoting
  that to cross-operator is a small, understood step. Bolting on libp2p
  is a ground-up rewrite.

### Scale — design for thousands, not millions

Realistic ceiling for a security-operator federation is **low thousands**.
Points of reference: Mastodon ~10k servers, Tor ~7k relays, Nostr ~2k
active relays. A niche-of-a-niche like threat-intel federation will not
exceed these.

**Design explicitly for 1k operators, with an escape hatch at 10k.**
Million-scale assumptions force Kafka/DHT/consensus theater that
strangles actual work.

### The hard problem is trust, not protocol

Every threat-intel federation that ignored trust became a spam cesspool
(early AlienVault OTX, half the ISAC world). Answers required:

- **Sybil resistance** — what stops an adversary spinning 50 fake
  operators to poison clustering? First-pass answer: **gated enrollment
  via a central registry signed by the project root**. Yes, centralized.
  "Centralized root, federated leaves" is Mastodon's model and it works.
  Decentralize only if adoption forces it. Don't premature-decentralize.
- **Adversarial join** — what stops an attacker running a decoy operator
  specifically to map *what other operators observe*? This is the
  terrifying one. Gossip must be **asymmetric by design**: publish
  simhashes and other lossy fingerprints, not raw session data. Answer
  queries with binary matches (yes/no + count + first-seen), not full
  session payloads. The attacker-operator learns "this simhash is
  known to someone," nothing more.
- **Jurisdictional blast radius** — IP addresses are PII under GDPR. An
  operator in Germany gossiping an attacker IP to an operator in
  Singapore may commit a crime. **Per-operator, per-field opt-out with a
  default-deny posture for PII-adjacent data** is non-negotiable.
  Geo-tagged operator registry entries let the federation enforce this at
  the protocol layer rather than the honor system.
- **Legal chill** — CFAA, NIS2, sector-specific rules. Having a clear
  "this operator chose to share X" audit trail per record protects
  everyone. Every gossiped fact carries the originating operator's
  signature.

### What to build first — the two-operator handshake

Build **one primitive and nothing else**: two operators who've manually
exchanged pubkeys making signed queries to each other to answer one
question — **"have you seen this SimHash?"**

Response: `{ seen: bool, count: int, first_seen: timestamp }`. Nothing
more. No sid, no decky, no IP, no raw session data.

Why: if that primitive doesn't produce value for two operators, scaling
it to a thousand won't either. If it does, the scaling is mostly
operational — directory service, retry/backoff, rate limits — which are
all solved problems. **The design risk lives entirely in the primitive,
not in the scale-out.**

Explicit non-goals for first iteration:
- No pub-sub.
- No DHT.
- No gossip protocol.
- No operator discovery.
- No multi-hop.

Just two pubkeys, one question, a signed answer.

### Sequencing

1. **Operator identity** — Ed25519 keypair per operator, generated at
   install. Self-signed manifest (operator name, pubkey, contact, geo).
2. **Two-operator handshake** — mTLS over HTTPS, pubkey pinning, one
   RPC: `QuerySimHash(hash) → {seen, count, first_seen}`. Manual peer
   config in YAML.
3. **Registry** — central signed directory of known operators, fetched
   on boot. Enables discovery without mandating central routing.
4. **Additional query types** — JA3/JA4 lookup, HASSH lookup, command-
   n-gram match. Same shape: lossy fingerprint in, binary+metadata out.
5. **Publish path** — operators periodically push new fingerprints to
   peers (gossiped, not polled). Signed, deduplicated by fingerprint.
6. **Clustering & visualization** — UI surface for "this simhash is
   known across N operators, first seen by operator-X on date-Y."

### Codebase-aware observations

- **`session_profile` *is* the federation wire format.** `schema_version`
  from day one is non-negotiable — retrofitting cross-operator
  compatibility after the fact is a nightmare.
- **SWARM mTLS is the starting point**, not the finishing point. The
  per-host fingerprint-pin pattern (memory:
  feedback_mtls_pin_per_host.md) extends naturally to per-operator pins.
- **The bus stays local.** Federation is cross-host in a way the bus was
  explicitly scoped away from ("cross-host federation is out of MVP
  scope"). A separate `decnet federation` worker is the right shape, not
  bridging the bus over TCP.
- **Attack surface.** Federation endpoints on operator hosts *are*
  targets. If the coordination layer is compromised, honeypots become
  attack infra. Bind federation RPC to a separate interface, separate
  cert chain, separate systemd unit. Assume the federation daemon will
  eventually be breached and design blast-radius containment into the
  architecture — it must not share credentials, sockets, or filesystem
  trust with the local DECNET workers.

### Open questions

1. **Who runs the root registry?** Project root (ANTI) as v2 default;
   path to handoff/multi-root federation in v3.
2. **Revocation** — how is a compromised operator kicked? Registry
   signs a revocation list, peers refuse queries from revoked pubkeys.
   Cache TTL?
3. **Rate-limiting adversarial joins** — a registered operator can still
   query-flood to enumerate fingerprints. Per-peer query budgets, with
   a reputation signal that decays silence and rewards useful
   publishing.
4. **Consent UX** — what does an operator opt into when they enable
   federation? Single toggle is wrong; per-category (fingerprints /
   profiles / commands / IPs) is right. Defaults matter more than
   flexibility.

### Trust model refinement — 2026-04-22 design review

The framing above (central signed registry, gated enrollment, revocation
lists, reputation algorithms) is **superseded by a social-trust model**
arrived at through adversarial design review. Captured here verbatim so
the iteration trail isn't lost.

**The governing insight:** trust is not technical, it is human. Instead
of solving cross-operator trust with crypto/PKI/reputation, **leave it
to humans**. Two operators meet at a conference, have beers, decide to
federate. Recurse ad infinitum. No zero-knowledge proofs, no
decentralized governance, no CRL theater.

This is a deliberate deferral of a hard problem, not a claim that the
hard problem is solved. The rest of this subsection documents why the
social-trust model holds up under attack and where its residual weaknesses
live.

#### Attacks considered and outcomes

**1. Transitive trust collapse.** First framing ("recurse ad infinitum")
implied A→B→C gossip flow, which is how PGP's web of trust died.
**Resolution:** model is hub-and-spoke, not transitive. Every federation
edge is a manual, mutually-made handshake ("beershake"). A learns that C
exists (because B mentioned C), but A does not federate with C until
A and C separately beershake. Topology metadata leaks (B tells A that
C exists, which C may not have consented to share), but gossip does not.

**2. Attackers go to conferences too.** Social trust filters for
"drinks beer at BSides," not "not-an-adversary." Ransomware affiliates
and red teams can stand up DECNET, be charming, and join. **Accepted.**
Social consequences scale better than cryptographic ones for this class
of problem: if operator A's sponsored peer B starts gossiping garbage,
A's other federates see that A brought B in — reputation damage is the
brake. Not perfect, but it's a real cost.

**3. The query IS the intel.** Aggregate-only responses
(`{seen, count, first_seen}`) don't defeat recon — a phishing operator
querying "has anyone seen `paypa1-security.com`?" learns whether their
cover domain has burned. **Resolution: federation is push-only, not
pull.** Peers send what they chose to send; nobody can ask on demand.
C still gets data, but not on-demand data. This closes the dangerous
recon lane outright.

**4. Compromised-peer inheritance.** A friend's DECNET master is a box
on the internet. When it gets rooted, the attacker inherits every
federation edge that admin held. **Conceded as a real risk.** No clean
mitigation beyond the push-only constraint (limits what the compromised
node can exfiltrate in real-time) and the hub-and-spoke constraint
(limits blast radius to that operator's direct peers).

**5. Revocation non-transitivity.** If trust is social, so is distrust.
A kicks B; Carol (who also federates with B) still relays to B.
**Resolution: see #2 — A's kick is visible to A's other federates,
sponsorship accountability propagates socially in real-time via the
topology-transparency mechanism (see below). Not a coordination
problem DECNET solves; one it exposes so humans can solve it.**

**6. Legal/compliance at enterprise scale.** GDPR, HIPAA, FFIEC,
data-residency — informal federation has no DPA and will not survive
first enterprise deal. **Resolution: write down the deferral.** v1
federation is explicitly for informal peer networks only. A DPA
framework gates any regulated-org federation; that is v3 scope.

#### The full model

- **Hub-and-spoke, pairwise beershakes.** No transitive trust.
- **Push-only, never pull.** Peers push what they choose; no on-demand
  queries, no recon surface.
- **Sponsorship-as-reputation.** A brought B in; if B misbehaves, A's
  reputation across A's other federates degrades. Social cost, real-time.
- **Hash-evidence on every contribution.** To prevent fabricated pushes
  that game contribution ratios, every shared fact must include a
  verifiable fingerprint (message sha256, cert fingerprint, artifact
  sha256) — not a free-text claim. "I saw domain X" without an artifact
  hash is not a contribution.
- **Contribution ratios, enforced per peer.** Pure consumers get starved;
  peers must push roughly as much as they receive. Paired with
  hash-evidence above so ratios can't be gamed with garbage.
- **Topology transparency.** Every federate can see the full federation
  graph from their vantage point: who sponsored whom, who kicked whom,
  contribution volumes. Makes sponsorship accountability observable in
  real-time rather than post-incident.
- **Omission-based canary watermarking.** Individualizing "saw domain X"
  across N peers is impossible (you can't watermark a string). Instead,
  A withholds X from peer 23 specifically; if X surfaces externally, A
  can triangulate across multiple omission canaries over time. Forensic
  tool, not preventive.

#### Accepted residuals

These are structural to gossip systems and are **accepted with
mitigation, not eliminated:**

- **Audit gap.** Misbehaving federates leak silently — queries (or in
  push-only, consumption) are supposed to happen. By the time a peer
  notices the leak, the data has already moved. Mitigation: omission
  canaries provide post-hoc forensic attribution; sponsorship
  accountability provides the social pressure to catch it faster.
- **Correlation-at-receiver.** C receives push from A, B, D, E. None
  shared much individually; C correlates across them to build a picture
  no sender authorized. Cannot be designed out without killing the
  federation's entire value proposition. Priced in, documented.
- **Push cadence as metadata.** Even push-only, timing/volume of what A
  pushes tells receivers about A's current coverage/posture. Low
  bandwidth, probably unfixable without batching jitter that hurts
  timeliness. Accepted.
- **Topology metadata leak.** B telling A that C exists (as part of the
  "recurse ad infinitum" socialization) is itself signal C may not have
  consented to share. In regulated sectors, even "bank X runs deception"
  is information. Minor, but noted.

#### Why the social-trust framing is correct *now*

The earlier subsection (central registry, gated enrollment, Ed25519
per-operator identities, signed revocation lists) is not wrong, it is
**premature**. Building that machinery before there is a real
federation with real users is the "million-scale assumptions that
strangle actual work" trap called out in the Scale section above. The
social-trust model ships when there are two friends with two
deployments who want to try it. The crypto/registry model ships when
there is a customer whose compliance team requires it.

What cannot be deferred: **the wire format**. `session_profile`,
`smtp_targets`, and future federation-adjacent tables must still carry
`schema_version` from day one. Privacy-preserving shape
(`{seen, count, first_seen}` aggregate-only, no attacker identity) is
the right posture independent of trust model — minimizing leak surface
is always correct.

#### What this changes in the earlier Open Questions

- **#1 Root registry** — no longer v2-blocking. Deferred to v3 or
  whenever a federation outgrows social coordination.
- **#2 Revocation** — answered. "A kicks B; A's other federates see it
  in the topology-transparency view and make their own call." No CRL.
- **#3 Rate-limiting adversarial joins** — partially answered. Push-only
  eliminates the query-flood vector. Per-peer rate limits on push still
  apply to prevent contribution-ratio gaming via spam.
- **#4 Consent UX** — unchanged. Per-category opt-in with default-deny
  on PII-adjacent data is still the right shape.

#### Second round — scope-verified pull as a complementary channel

Follow-up design review revisited the "query IS the intel" problem from
a different angle. Push-only closes the recon attack but sacrifices the
defender's most useful query shape: "has anyone seen anything new about
MY brand today?"

**Proposal:** operators verify domain scope at registration time (ACME
dns-01 pattern — TXT record challenge), and pull queries are restricted
to data about scope-verified domains. BigBank can query about
`bigbank.com`; they cannot query about `competitor.com`.

**This is a genuine addition, not a replacement for push-only.** Both
channels coexist with different threat models:

- **Push-only channel** — peer-volunteered gossip. Handles the case
  where the domain being attacked is one the defender does NOT own
  (lookalikes, typosquats, newly-registered phishing infra). This is
  the defender's primary use case and scope-verified pull cannot serve
  it without fuzzy matching, which attackers abuse.
- **Scope-verified pull channel** — bounded "what's new about my
  verified scope" queries. Narrow, auditable, recon-resistant.

**Attacks considered on the pull channel:**

1. **Indirect-reference / lookalike queries.** The intel defenders most
   need is about domains they DON'T own (`bigbank-secure-login.support`
   targeting BigBank). Allowing fuzzy/lookalike matching under "claimed
   typo of my scope" reopens the recon lane. **Resolution: exact-match
   only on the pull channel. Lookalike intel flows through push-only.**
2. **Domain graveyard.** Attacker buys an expired domain, DNS-verifies,
   pulls historical phishing intel for a brand they're about to revive.
   **Mitigation: scope applies prospectively only — queries bounded to
   intel indexed since the operator's verification timestamp.** Bake in
   from day one, hard to retrofit.
3. **Subdomain scope inference.** Wildcard matching (`*.bigbank.com`)
   invites overreach. **Resolution: explicit list of scoped domains,
   each individually DNS-verified. No wildcard inference.**
4. **Self-lookup leaks coverage maps to the asker.** BigBank querying
   their scope learns which peers have visibility into BigBank-targeting
   campaigns. **Resolution: aggregate-only response
   (`{seen, count, first_seen}`) with no per-peer attribution.** Already
   implicit.
5. **MSSP multi-tenant churn.** An MSSP claims scope over 200 client
   brands; clients leave, the DECNET retains ex-scope.
   **Mitigation: periodic re-verification (weekly cadence) of every
   scoped domain's TXT record.**

**Residual, accepted:** scope-verified pull cannot serve queries about
domains the defender doesn't control. That's the structural limit —
push-only covers it.

**Net model for v2 federation:**
- Identity: Ed25519 keypair + DNS-verified scope list (explicit, not
  wildcard, periodic re-verify).
- Channel 1 — push: hash-evidenced contributions, peer-volunteered, no
  query surface.
- Channel 2 — pull: scope-verified, exact-match, prospective-only,
  aggregate-response, rate-limited.
