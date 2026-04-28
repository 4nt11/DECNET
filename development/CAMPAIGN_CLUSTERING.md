# Campaign Clustering — Design

**Status:** pre-implementation. This doc is the spec; code follows.

**Roadmap entry:** `DEVELOPMENT.md` — Detection & Intelligence → "Attack campaign clustering".

## Premise

A *campaign* is a coordinated set of attacker actions that share intent, tooling, or operator — observable at DECNET as recurring patterns across `attackers`, `sessions`, `fingerprints`, `credentials`, and `payloads`.

We will not write clustering code until we can **simulate campaigns with ground-truth labels** and run a clusterer against those labels. The simulator is the specification for what a campaign is; the algorithm is replaceable.

Order of work, strictly:

1. Campaign DSL + generator (produces synthetic events with `campaign_id` / `actor_id` labels).
2. Adversarial scenario fixtures (the 6 below).
3. Metric harness (ARI + homogeneity + completeness + singleton recall).
4. Dumbest viable clusterer (connected components on a similarity graph). Must pass all 6 fixtures.
5. Pipeline integration (`decnet clusterer` worker, `campaigns` table, dashboard).
6. Replay tier — public datasets / Honeynet SSH logs through the live collector. Reality check, not optional forever.

Steps 1–3 are the durable artifact. Step 4 is the first throwaway algorithm.

---

## Phase Vocabulary: Unified Kill Chain

Phase names use the **Unified Kill Chain** (Pols, 2017), 18 phases across 3 stages. UKC maps cleanly to MITRE ATT&CK tactics, which means the phase labels we emit in synthetic data are the same labels the future TTP-tagging worker (also in `DEVELOPMENT.md`) will produce. Fixtures become reusable across both features instead of needing renaming.

| Stage | Phases |
|---|---|
| **In** (initial foothold) | Reconnaissance, Resource Development, Weaponization, Delivery, Social Engineering, Exploitation, Persistence, Defense Evasion, Command & Control |
| **Through** (network propagation) | Pivoting, Discovery, Privilege Escalation, Execution, Credential Access, Lateral Movement |
| **Out** (action on objectives) | Collection, Exfiltration, Impact, Objectives |

**Honeypot observability.** A honeypot does not see the entire chain. Pre-target phases (OSINT Reconnaissance, Resource Development, Weaponization, Social Engineering) happen before any decky is touched. We observe roughly 14 of 18:

- **In:** Delivery, Exploitation, Persistence, Defense Evasion, Command & Control
- **Through:** Pivoting, Discovery, Privilege Escalation, Execution, Credential Access, Lateral Movement
- **Out:** Collection, Exfiltration, Impact, Objectives

The DSL allows the full enum so a campaign spec can describe an end-to-end story, but the generator emits no events for unobservable phases (and warns on them). MazeNET makes Pivoting and Lateral Movement first-class — that's where DECNET has *more* signal than a single-host honeypot, not less.

Each phase carries default tool-signature templates the DSL can override per-campaign. Examples:

- `discovery` → defaults: `whoami`, `id`, `uname -a`, `netstat -tnp`, `cat /etc/passwd`
- `persistence` → defaults: crontab edit, `~/.ssh/authorized_keys` write, systemd unit drop, `.bashrc` append
- `credential_access` → defaults: `/etc/shadow` read, browser-cred files, SSH key harvest
- `lateral_movement` → defaults: SSH/WinRM/SMB pivot to another decky in the same MazeNET segment

---

## 1. Campaign DSL

A campaign is a *causal story*, not a bag of events. Generator consumes YAML, emits a stream of synthetic records into the test DB with ground-truth labels.

```yaml
campaign:
  id: c-apt-fauxbear-01
  actors:
    - id: a-001
      asn: 14061              # DigitalOcean
      ip_pool: rotating       # rotating | sticky | tor
      ja3: 769,4865-...       # tool fingerprint, shared within campaign
      hassh: aae6b9...
      hours_active_utc: [22, 23, 0, 1, 2, 3]
      jitter_seconds: 90
      role: intrusion         # intrusion | post-exploit | exfil — for multi-operator campaigns
    - id: a-002
      asn: 14061
      ip_pool: sticky
      ja3: 769,4865-...       # same tool, different operator
      hassh: aae6b9...
      hours_active_utc: [14, 15, 16, 17]
      jitter_seconds: 30
      role: post-exploit
  phases:                     # UKC phase enum
    - name: delivery
      actor: a-001
      tool_signature: { user_agent: "Mozilla/5.0 (compatible; Nmap)" }
      target_selector: { service: any, count: 50 }
      dwell_seconds: 1
    - name: exploitation
      actor: a-001
      tool_signature: { payload_hash: deadbeef..., cve: CVE-2024-XXXX }
      target_selector: { service: http, port: 8080 }
      success_rate: 0.2
    - name: persistence
      actor: a-001
      tool_signature: { commands: ["wget", "chmod +x", "./", "crontab -e"] }
      target_selector: { decky: previous_success }
    - name: command_and_control
      actor: a-001
      tool_signature: { c2_callback: evil.example.com, beacon_jitter_seconds: 30 }
    - name: discovery
      actor: a-002              # handoff to second operator
      tool_signature: { commands: ["whoami", "id", "uname -a", "ip route", "arp -a"] }
    - name: lateral_movement
      actor: a-002
      tool_signature: { protocol: ssh, credential_source: harvested }
      target_selector: { decky: adjacent_in_mazenet }
    - name: collection
      actor: a-002
      tool_signature: { paths: ["/var/lib/mysql/*", "/home/*/Documents/*"] }
    - name: exfiltration
      actor: a-002
      tool_signature: { c2_callback: evil.example.com, payload_hash: deadbeef... }
  duration_days: 7
  pause_windows: []           # for the "campaign that pauses" scenario
```

**Generator contract:**

- Input: list of campaign YAMLs + `noise: { scanner_count, ratio }`.
- Output: rows in `attackers` / `sessions` / `fingerprints` / `credentials_attempts` / `payloads`, each tagged with a `_truth_campaign_id` and `_truth_actor_id` column (test-only, stripped before clustering runs).
- Deterministic given a seed.
- Validates phase names against the UKC enum; warns on unobservable phases (emits no events for them).

The generator lives at `tests/factories/campaign_factory.py`. The DSL parser is the spec; if a real attacker pattern can't be expressed in it, the DSL is incomplete and we extend it before extending the clusterer.

---

## 2. Adversarial Scenario Fixtures

Six fixtures. Each is a YAML file under `tests/fixtures/campaigns/` plus an expected-bounds file. CI runs the clusterer against all six; any regression fails the build.

| # | Name | Setup | Pass condition |
|---|---|---|---|
| 1 | `shared_wordlist` | 2 distinct campaigns, both use rockyou-top1k for SSH brute (Credential Access phase) | Must NOT merge — credential overlap alone is insufficient signal |
| 2 | `vpn_hopping` | 1 campaign, 1 actor, IPs rotate across 5 ASNs over 3 days, JA3/HASSH stable, full Delivery→C2→Discovery chain | Must NOT split — actor identity survives IP churn |
| 3 | `lone_wolf` | 1 opportunistic scanner, Delivery phase only, no follow-up, no shared signals | Must stay singleton — not absorbed into any campaign |
| 4 | `paused_campaign` | 1 campaign, active days 1–2 (Delivery, Exploitation), silent days 3–5, active days 6–7 (Discovery, Lateral Movement, Exfiltration) | Must NOT split into two campaigns — temporal window must accommodate operator pauses |
| 5 | `multi_operator` | 1 campaign, 2 actors with distinct UKC roles: actor A handles Delivery→Exploitation→Persistence→C2 on UTC night shift, actor B handles Discovery→Lateral Movement→Collection→Exfiltration on UTC day shift, different IPs/ASNs, shared C2 callback + payload hash | Must merge — shared tooling and phase handoff > diverged infra |
| 6 | `noise_floor` | All 5 above + 10× random Delivery-only scanners drawn from a noise distribution | All 5 must still resolve correctly; scanners stay singleton |

Fixture 5 is the load-bearing one for UKC: a real campaign frequently splits operators along the In/Through/Out boundary, and a clusterer that only looks at IP/ASN will miss it. Phase-handoff is itself a feature the algorithm can use.

**Bounds per fixture** (in `expected.yaml` next to each):

```yaml
adjusted_rand_index: { min: 0.85 }
homogeneity:         { min: 0.90 }   # no false merges
completeness:        { min: 0.80 }   # no false splits
singleton_recall:    { min: 0.95 }   # for lone_wolf / noise scanners
```

Bounds are deliberately loose at first — we ratchet them up as the algorithm improves. Loosening a bound to make CI pass requires a PR comment justifying it.

---

## 3. Metric Harness

`tests/clustering/metrics.py`. Decided **before** any algorithm exists, so we don't pick the metric that flatters the result.

- **Adjusted Rand Index** — headline. Compares predicted vs. truth labels, corrects for chance.
- **Homogeneity** — each predicted cluster contains only members of one true campaign. Catches false merges.
- **Completeness** — all members of a true campaign land in the same predicted cluster. Catches false splits.
- **Singleton recall** — fraction of true singletons (lone wolves, noise) that stay singleton.

Homogeneity and completeness trade off; both must be reported. A single number hides which direction the algorithm is failing.

**Per-fixture report** is dumped as JSON on every CI run, not just pass/fail, so we can watch trends over time.

---

## 4. First Algorithm (after 1–3 are green)

Connected-components on a similarity graph. No ML.

- Nodes: attackers (or sessions, TBD — see open questions).
- Edges: weighted similarity, threshold to binarize.
- Edge weight = sum of:
  - JA3/JA4/HASSH exact match: high
  - Payload hash exact match: high
  - C2 callback domain/IP exact match: high
  - **Phase-handoff signal:** actor X ends in C2/Persistence on a decky, actor Y begins Discovery/Lateral Movement on the same decky within window W: medium-high. Defeats fixture 5 even when IP/ASN diverge.
  - Credential-list Jaccard: low (defeated by fixture 1)
  - Command-sequence Jaccard, bucketed by UKC phase: medium
  - Temporal proximity (within window W): low multiplier
  - ASN match: very low
- Edge threshold and feature weights are config, tuned against the 6 fixtures.

If connected-components passes all 6, ship it. DBSCAN/HDBSCAN/graph-community algorithms are deferred until a fixture proves CC inadequate.

---

## 5. Pipeline Integration

- New worker: `decnet clusterer`. Bus consumer on `attacker.scored` and `attacker.observed`.
- Re-cluster strategy: incremental on new attacker arrivals, full re-cluster nightly.
- Storage: `campaigns` table (UUID PK, per the `feedback_uuid_over_natural_keys` rule); `attackers.campaign_id` FK nullable.
- Bus signal: `campaign.{id}.formed` / `campaign.{id}.updated`. Document in `wiki-checkout/Service-Bus.md` per the `feedback_wiki_bus_signals` rule.
- Dashboard: Campaigns list page + CampaignDetail (aggregated AttackerDetail, with a UKC phase timeline visualization showing which phases each actor in the campaign executed).

---

## 6. Replay Tier (post-v1)

Public-dataset replay through the real collector. Confirms our fixtures encode realistic patterns, not just our assumptions.

Candidate sources:
- Honeynet Project SSH session corpora.
- DShield daily summaries.
- Our own production data once it accumulates.

This is where we discover whether the DSL is missing a dimension. Schedule it; don't punt forever.

---

## Risks

1. **Simulator encodes our assumptions.** Real attackers may not match. Mitigation: replay tier (§6).
2. **Bound creep.** Loosening fixture bounds to ship is the failure mode. Mitigation: bound changes require PR justification.
3. **Feature drift.** Sniffer fingerprint coverage changes the available signal. Mitigation: feature set is configurable; fixtures regenerate from the DSL when features change.
4. **UKC phase inference accuracy.** The clusterer relies on phase labels per session — those have to come from somewhere. Pre-TTP-tagging worker, the DSL emits them as ground truth in synthetic data, and the live pipeline uses heuristic phase assignment (command keywords, port/protocol). This is a known approximation; tightens once the TTP-tagging worker ships.
5. **Cost of full re-cluster.** At fleet scale, nightly re-cluster on millions of attackers is expensive. Mitigation: incremental-first, full nightly is a fallback we may drop.

## Open questions

- **Cluster nodes: attackers or sessions?** Leaning attackers (already deduped by `attacker_uuid`), but session-level may catch campaigns that span multiple attacker identities. Decide after fixture 5 (`multi_operator`).
- **Time window W** for temporal-proximity and phase-handoff edges: 24h? 7d? Tuned against fixture 4 (`paused_campaign`).
- **Phase inference at runtime.** Do we ship a heuristic phase classifier alongside the clusterer, or block on the TTP-tagging worker landing first? Heuristic is faster but is technical debt against the future ATT&CK-tagged version.
- **API exposure.** Do we expose campaigns in the public API or admin-only at first? Admin-only until we have UI for false-positive correction.
