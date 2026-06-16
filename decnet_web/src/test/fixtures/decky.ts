// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Decky } from '../../components/DeckyFleet/types';

export type DeckyFixture = Decky;

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
