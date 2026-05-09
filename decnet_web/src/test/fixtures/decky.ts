export interface DeckyFixture {
  name: string;
  ip: string;
  services: string[];
  distro: string;
  hostname: string;
  archetype: string | null;
  service_config: Record<string, Record<string, unknown>>;
  mutate_interval: number | null;
  last_mutated: number;
  swarm?: {
    host_uuid: string;
    host_name: string;
    state: string;
    last_error: string | null;
    last_seen: string | null;
  };
}

export const makeDecky = (overrides: Partial<DeckyFixture> = {}): DeckyFixture => ({
  name: 'decoy-01',
  ip: '10.10.10.10',
  services: ['ssh', 'http'],
  distro: 'debian-12',
  hostname: 'fileserver-01',
  archetype: 'workstation',
  service_config: {},
  mutate_interval: null,
  last_mutated: 0,
  ...overrides,
});
