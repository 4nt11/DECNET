// SPDX-License-Identifier: AGPL-3.0-or-later
/* eslint-disable @typescript-eslint/no-explicit-any */

// Mirrors decnet/web/db/models/attacker_intel.py — server returns the row
// fields plus null gaps where a provider hasn't answered yet. We treat
// every column as optional on the wire.
export interface IntelRow {
  attacker_uuid: string;
  attacker_ip: string;
  schema_version?: number;
  aggregate_verdict?: 'malicious' | 'suspicious' | 'benign' | 'unknown' | null;
  greynoise_classification?: string | null;
  greynoise_raw?: any;
  greynoise_queried_at?: string | null;
  abuseipdb_score?: number | null;
  abuseipdb_raw?: any;
  abuseipdb_queried_at?: string | null;
  feodo_listed?: boolean | null;
  feodo_raw?: any;
  feodo_queried_at?: string | null;
  threatfox_listed?: boolean | null;
  threatfox_raw?: any;
  threatfox_queried_at?: string | null;
  cached_at?: string | null;
  expires_at?: string | null;
}
