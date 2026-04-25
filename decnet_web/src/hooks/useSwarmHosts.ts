import { useCallback, useEffect, useState } from 'react';
import api from '../utils/api';

export interface SwarmHost {
  uuid: string;
  name: string;
  address: string;
  agent_port: number;
  status: string;
  last_heartbeat: string | null;
}

/**
 * Lookup of enrolled swarm hosts. One-shot fetch on mount, with a manual
 * refresh callback. Used to resolve `target_host_uuid` → display name in
 * places where we don't already have a host name in hand (topology list,
 * war-map header).
 *
 * Failure is treated as "no agents enrolled" — callers fall back to the
 * uuid prefix or a generic label rather than blocking on this lookup.
 */
export function useSwarmHosts(): {
  hosts: SwarmHost[];
  byUuid: Map<string, SwarmHost>;
  refresh: () => Promise<void>;
} {
  const [hosts, setHosts] = useState<SwarmHost[]>([]);

  const refresh = useCallback(async () => {
    try {
      const { data } = await api.get<SwarmHost[]>('/swarm/hosts');
      setHosts(data ?? []);
    } catch {
      setHosts([]);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const byUuid = new Map(hosts.map((h) => [h.uuid, h]));
  return { hosts, byUuid, refresh };
}
