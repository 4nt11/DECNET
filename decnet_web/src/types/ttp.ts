export interface TechniqueRow {
  technique_id: string;
  technique_name: string | null;
  sub_technique_id: string | null;
  sub_technique_name: string | null;
  tactic: string;
  count: number;
  first_seen: string;
  last_seen: string;
  confidence_max: number;
  mitre_url?: string | null;
}

export interface TTPTagDetailRow {
  uuid: string;
  source_kind: string;
  source_id: string;
  attacker_uuid: string | null;
  identity_uuid: string | null;
  session_id: string | null;
  decky_id: string | null;
  tactic: string;
  technique_id: string;
  technique_name: string | null;
  sub_technique_id: string | null;
  sub_technique_name: string | null;
  confidence: number;
  rule_id: string;
  rule_version: number;
  evidence: Record<string, unknown>;
  attack_release: string;
  created_at: string;
  mitre_url?: string | null;
}

export interface GroupRef {
  group_id: string;
  name: string;
  aliases: string[];
  mitre_url: string | null;
}
