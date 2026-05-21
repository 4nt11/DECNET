/** Shared types for the AttackerDetail page surface. The canonical
 *  definitions live here; AttackerDetail.tsx re-exports the public
 *  ones (BehaviouralObservation, AttributionPrimitiveState) so
 *  external importers stay stable through the refactor. */

export interface AttackerBehavior {
  os_guess: string | null;
  hop_distance: number | null;
  tcp_fingerprint: {
    window?: number | null;
    wscale?: number | null;
    mss?: number | null;
    options_sig?: string;
    has_sack?: boolean;
    has_timestamps?: boolean;
    tos?: number | null;
    dscp?: number | null;
    ecn?: number | null;
    ipid_class?: string | null;
    isn_class?: string | null;
  } | null;
  retransmit_count: number;
  behavior_class: string | null;
  beacon_interval_s: number | null;
  beacon_jitter_pct: number | null;
  tool_guesses: string[] | null;
  timing_stats: {
    event_count?: number;
    duration_s?: number;
    mean_iat_s?: number | null;
    median_iat_s?: number | null;
    stdev_iat_s?: number | null;
    min_iat_s?: number | null;
    max_iat_s?: number | null;
    cv?: number | null;
  } | null;
  phase_sequence: {
    recon_end_ts?: string | null;
    exfil_start_ts?: string | null;
    exfil_latency_s?: number | null;
    large_payload_count?: number;
  } | null;
  updated_at?: string;
}

export interface CommandRow {
  service: string;
  decky: string;
  command: string;
  timestamp: string;
}

export interface AttackerData {
  uuid: string;
  ip: string;
  identity_id?: string | null;
  first_seen: string;
  last_seen: string;
  event_count: number;
  service_count: number;
  decky_count: number;
  services: string[];
  deckies: string[];
  traversal_path: string | null;
  is_traversal: boolean;
  bounty_count: number;
  credential_count: number;
  // Heterogeneous fingerprint blobs — schema varies per fp_type and
  // is rendered by the per-type Fp* components in AttackerDetail.tsx.
  fingerprints: unknown[];
  commands: CommandRow[];
  country_code: string | null;
  country_source: string | null;
  asn: number | null;
  as_name: string | null;
  bgp_prefix: string | null;
  asn_source: string | null;
  rpki_status: string | null;
  rpki_source: string | null;
  ptr_record: string | null;
  updated_at: string;
  behavior: AttackerBehavior | null;
  service_activity?: {
    interacted: string[];
    scanned: string[];
  };
  ip_leaks?: Array<{
    timestamp: string;
    decky?: string;
    service?: string;
    bounty_type: string;
    payload: {
      source_ip?: string;
      real_ip_claim?: string;
      source_header?: string;
      headers_seen?: Record<string, string>;
    };
  }>;
  ip_leaks_total?: number;
  observations?: BehaviouralObservation[];
}

export interface BehaviouralObservation {
  primitive: string;
  value: unknown;
  confidence: number;
  ts?: number;
  source?: string;
}

export interface AttributionPrimitiveState {
  primitive: string;
  current_value: unknown;
  state: 'unknown' | 'stable' | 'drifting' | 'conflicted' | 'multi_actor';
  confidence: number;
  observation_count: number;
  last_change_ts: number;
  last_observation_ts: number;
}

export interface ArtifactLog {
  id: number;
  timestamp: string;
  decky: string;
  service: string;
  fields: string;
}

export interface SessionLog {
  id: number;
  timestamp: string;
  decky: string;
  service: string;
  fields: string;
}

export interface SmtpTargetRow {
  domain: string;
  count: number;
  first_seen: string;
  last_seen: string;
}

export interface MailLog {
  id: number;
  timestamp: string;
  decky: string;
  service: string;
  fields: string;
}
