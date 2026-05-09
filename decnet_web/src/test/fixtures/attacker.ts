export interface AttackerFixture {
  uuid: string;
  ip: string;
  identity_id: string | null;
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
  fingerprints: unknown[];
  commands: { service: string; decky: string; command: string; timestamp: string }[];
  country_code: string | null;
  country_source: string | null;
  asn: number | null;
  as_name: string | null;
  asn_source: string | null;
  ptr_record: string | null;
  updated_at: string;
  behavior: null;
  service_activity: { interacted: string[]; scanned: string[] };
  observations: never[];
}

export const makeAttacker = (overrides: Partial<AttackerFixture> = {}): AttackerFixture => ({
  uuid: '11111111-1111-1111-1111-111111111111',
  ip: '198.51.100.10',
  identity_id: null,
  first_seen: '2026-05-01T10:00:00Z',
  last_seen: '2026-05-09T11:00:00Z',
  event_count: 12,
  service_count: 2,
  decky_count: 1,
  services: ['ssh', 'http'],
  deckies: ['decoy-01'],
  traversal_path: null,
  is_traversal: false,
  bounty_count: 0,
  credential_count: 0,
  fingerprints: [],
  commands: [],
  country_code: 'US',
  country_source: 'maxmind',
  asn: 64500,
  as_name: 'EXAMPLE-AS',
  asn_source: 'maxmind',
  ptr_record: null,
  updated_at: '2026-05-09T11:00:00Z',
  behavior: null,
  service_activity: { interacted: ['ssh'], scanned: ['http'] },
  observations: [],
  ...overrides,
});
