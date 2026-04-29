import { useEffect, useState } from 'react';
import api from '../utils/api';

/** Shape of /api/v1/topologies/services. */
export interface ServiceRegistry {
  /** All registered service slugs (e.g. 'ssh', 'http', 'mysql'). */
  services: string[];
  /** Subset that runs once fleet-wide; not addable to a single decky. */
  fleet_singletons: string[];
  /** Per-decky-eligible (services minus fleet_singletons). */
  perDecky: string[];
}

const EMPTY: ServiceRegistry = { services: [], fleet_singletons: [], perDecky: [] };

// Module-scoped cache.  The registry is keyed by the running master and
// changes only when the operator drops a new BYOS file or installs a
// plugin, neither of which happens during a normal session — caching
// across components avoids a re-fetch on every drawer open.
let cached: ServiceRegistry | null = null;
let inflight: Promise<ServiceRegistry> | null = null;

async function fetchRegistry(): Promise<ServiceRegistry> {
  if (cached) return cached;
  if (inflight) return inflight;
  inflight = api
    .get<{ services: string[]; fleet_singletons?: string[] }>('/topologies/services')
    .then((res) => {
      const services = res.data.services ?? [];
      const singletons = res.data.fleet_singletons ?? [];
      const singletonSet = new Set(singletons);
      const reg: ServiceRegistry = {
        services,
        fleet_singletons: singletons,
        perDecky: services.filter((s) => !singletonSet.has(s)),
      };
      cached = reg;
      return reg;
    })
    .catch(() => EMPTY)
    .finally(() => { inflight = null; });
  return inflight;
}

/** Reset the cache; call from tests or after a BYOS install. */
export function invalidateServiceRegistry(): void {
  cached = null;
}

/** Lazily load the service registry.  Returns ``EMPTY`` until the first
 * fetch resolves.  Errors fall through to ``EMPTY`` (the live add/remove
 * endpoints will still fail closed at submit time). */
export function useServiceRegistry(): ServiceRegistry {
  const [reg, setReg] = useState<ServiceRegistry>(cached ?? EMPTY);
  useEffect(() => {
    let cancelled = false;
    fetchRegistry().then((r) => { if (!cancelled) setReg(r); });
    return () => { cancelled = true; };
  }, []);
  return reg;
}
