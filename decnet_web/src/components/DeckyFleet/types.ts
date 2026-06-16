// SPDX-License-Identifier: AGPL-3.0-or-later
/** Wire + UI types for the DeckyFleet page surface. The canonical
 *  definitions live here; DeckyFleet.tsx re-exports the public ones
 *  through this barrel so external siblings can import without
 *  reaching across the page boundary. */

export interface SwarmMeta {
  host_uuid: string;
  host_name: string;
  host_address: string;
  host_status: string;
  state: string;
  last_error: string | null;
  last_seen: string | null;
}

export interface Decky {
  name: string;
  ip: string;
  services: string[];
  distro: string;
  hostname: string;
  archetype: string | null;
  service_config: Record<string, Record<string, unknown>>;
  mutate_interval: number | null;
  last_mutated: number;
  swarm?: SwarmMeta;
}

export interface SwarmDeckyRaw {
  decky_name: string;
  decky_ip: string | null;
  host_uuid: string;
  host_name: string;
  host_address: string;
  host_status: string;
  services: string[];
  state: string;
  last_error: string | null;
  last_seen: string | null;
  hostname: string | null;
  distro: string | null;
  archetype: string | null;
  service_config: Record<string, Record<string, unknown>>;
  mutate_interval: number | null;
  last_mutated: number;
}

export interface Archetype {
  slug: string;
  name: string;
  services: string[];
  icon: string;
}

export type FilterKey = 'all' | 'active' | 'hot' | 'idle';
export type DeckyStatus = 'active' | 'hot' | 'idle';
