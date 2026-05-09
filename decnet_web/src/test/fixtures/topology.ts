export interface TopologyFixture {
  id: string;
  name: string;
  mode: string;
  target_host_uuid: string | null;
  status: string;
  version: number;
}

export const makeTopology = (overrides: Partial<TopologyFixture> = {}): TopologyFixture => ({
  id: '44444444-4444-4444-4444-444444444444',
  name: 'corp-net-01',
  mode: 'flat',
  target_host_uuid: null,
  status: 'active',
  version: 1,
  ...overrides,
});
