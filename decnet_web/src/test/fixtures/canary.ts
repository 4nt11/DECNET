export interface CanaryTokenFixture {
  uuid: string;
  kind: 'http' | 'dns' | 'aws_passive';
  decky_name: string;
  topology_id: string | null;
  blob_uuid: string | null;
  instrumenter: string | null;
  generator: string | null;
  placement_path: string;
  callback_token: string;
  placed_at: string;
  last_triggered_at: string | null;
  trigger_count: number;
  created_by: string;
  state: 'planted' | 'revoked' | 'failed';
  last_error: string | null;
}

export interface CanaryBlobFixture {
  uuid: string;
  sha256: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  uploaded_by: string;
  uploaded_at: string;
  token_count: number;
}

export const makeCanaryToken = (
  overrides: Partial<CanaryTokenFixture> = {},
): CanaryTokenFixture => ({
  uuid: '22222222-2222-2222-2222-222222222222',
  kind: 'http',
  decky_name: 'decoy-01',
  topology_id: null,
  blob_uuid: null,
  instrumenter: 'git_config',
  generator: 'git_config',
  placement_path: '/etc/.git/config',
  callback_token: 'abc123token',
  placed_at: '2026-05-01T10:00:00Z',
  last_triggered_at: null,
  trigger_count: 0,
  created_by: 'admin',
  state: 'planted',
  last_error: null,
  ...overrides,
});

export const makeCanaryBlob = (
  overrides: Partial<CanaryBlobFixture> = {},
): CanaryBlobFixture => ({
  uuid: '33333333-3333-3333-3333-333333333333',
  sha256: 'a'.repeat(64),
  filename: 'creds.json',
  content_type: 'application/json',
  size_bytes: 1024,
  uploaded_by: 'admin',
  uploaded_at: '2026-05-01T10:00:00Z',
  token_count: 0,
  ...overrides,
});
