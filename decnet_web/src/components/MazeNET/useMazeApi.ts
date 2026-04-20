import { useCallback } from 'react';
import api from '../../utils/api';
import { DEFAULT_SERVICES } from './data';
import type { ServiceDef } from './data';
import type { Net, MazeNode, Edge, DeckyNode, PendingChange } from './types';

interface LANRow {
  id: string;
  name: string;
  subnet: string;
  is_dmz: boolean;
  x?: number | null;
  y?: number | null;
}

interface DeckyRow {
  uuid: string;
  name: string;
  services: string[];
  decky_config?: Record<string, unknown> | null;
  ip?: string | null;
  state: string;
  x?: number | null;
  y?: number | null;
}

interface EdgeRow {
  id: string;
  decky_uuid: string;
  lan_id: string;
  is_bridge: boolean;
  forwards_l3: boolean;
}

interface TopologySummary {
  id: string;
  name: string;
  mode: string;
  status: string;
  version: number;
}

interface TopologyDetail {
  topology: TopologySummary;
  lans: LANRow[];
  deckies: DeckyRow[];
  edges: EdgeRow[];
}

interface HydratedTopology {
  topology: TopologySummary;
  nets: Net[];
  nodes: MazeNode[];
  edges: Edge[];
}

/** Adapt the Phase-3 TopologyDetail wire shape to canvas entities.
 *  Backend edges are decky↔LAN membership (bipartite); we surface them
 *  as node-in-net placement. Decky-to-decky traffic edges are derived
 *  from shared-LAN co-membership for now (Step 4 may refine this). */
export function adaptTopology(detail: TopologyDetail): HydratedTopology {
  const nets: Net[] = detail.lans.map((lan, i) => ({
    id: lan.id,
    label: lan.name.toUpperCase(),
    cidr: lan.subnet,
    kind: lan.is_dmz ? 'dmz' : 'subnet',
    x: lan.x ?? 40 + (i % 3) * 320,
    y: lan.y ?? 40 + Math.floor(i / 3) * 280,
    w: 300,
    h: 240,
  }));

  /* A decky sits in the first LAN it attaches to. */
  const firstLanFor = new Map<string, string>();
  for (const e of detail.edges) {
    if (!firstLanFor.has(e.decky_uuid)) firstLanFor.set(e.decky_uuid, e.lan_id);
  }

  const nodes: MazeNode[] = detail.deckies.map((d, i): DeckyNode => ({
    kind: 'decky',
    id: d.uuid,
    netId: firstLanFor.get(d.uuid) ?? (nets[0]?.id ?? ''),
    name: d.name,
    archetype: 'linux-server',
    services: d.services,
    status: d.state === 'running' ? 'active' : d.state === 'failed' ? 'hot' : 'idle',
    x: d.x ?? 20 + (i % 2) * 160,
    y: d.y ?? 60 + Math.floor(i / 2) * 90,
    ip: d.ip ?? undefined,
    decky_config: d.decky_config ?? undefined,
  }));

  /* Derive decky-to-decky edges from shared-LAN membership. */
  const byLan = new Map<string, string[]>();
  for (const e of detail.edges) {
    const arr = byLan.get(e.lan_id) ?? [];
    arr.push(e.decky_uuid);
    byLan.set(e.lan_id, arr);
  }
  const seen = new Set<string>();
  const edges: Edge[] = [];
  for (const [lanId, members] of byLan) {
    for (let i = 0; i < members.length; i++) {
      for (let j = i + 1; j < members.length; j++) {
        const key = `${members[i]}::${members[j]}`;
        if (seen.has(key)) continue;
        seen.add(key);
        edges.push({
          id: `${lanId}-${members[i]}-${members[j]}`,
          from: members[i],
          to: members[j],
          traffic: 'idle',
        });
      }
    }
  }

  return { topology: detail.topology, nets, nodes, edges };
}

export interface MazeApi {
  listTopologies: () => Promise<TopologySummary[]>;
  getTopology:    (id: string) => Promise<HydratedTopology>;
  getServices:    () => Promise<ServiceDef[]>;
  getNextIp:      (topologyId: string, lanId: string) => Promise<string>;
  getNextSubnet:  (base: string) => Promise<string>;
  commit:         (topologyId: string, changes: PendingChange[]) => Promise<void>;
}

export function useMazeApi(toast?: (msg: string) => void): MazeApi {
  const listTopologies = useCallback(async () => {
    const { data } = await api.get('/topologies/');
    return (data?.data ?? []) as TopologySummary[];
  }, []);

  const getTopology = useCallback(async (id: string) => {
    const { data } = await api.get<TopologyDetail>(`/topologies/${id}`);
    return adaptTopology(data);
  }, []);

  const getServices = useCallback(async () => {
    try {
      const { data } = await api.get<{ services: string[] }>('/topologies/services');
      const known = new Map(DEFAULT_SERVICES.map((s) => [s.slug, s]));
      return data.services.map(
        (slug) =>
          known.get(slug) ?? {
            slug,
            name: slug.toUpperCase(),
            port: 0,
            proto: 'tcp' as const,
            icon: 'circle',
            risk: 'low' as const,
          },
      );
    } catch {
      return DEFAULT_SERVICES;
    }
  }, []);

  const getNextIp = useCallback(async (topologyId: string, lanId: string) => {
    const { data } = await api.get<{ subnet: string; ip: string }>(
      `/topologies/${topologyId}/lans/${lanId}/next-ip`,
    );
    return data.ip;
  }, []);

  const getNextSubnet = useCallback(async (base: string) => {
    const { data } = await api.get<{ subnet: string }>(
      `/topologies/next-subnet`,
      { params: { base } },
    );
    return data.subnet;
  }, []);

  const commit = useCallback(
    async (_topologyId: string, changes: PendingChange[]) => {
      /* Phase-3 Steps 3–5 land the real endpoints. For now, just surface. */
      console.log('[MazeNET] commit stub — pending changes:', changes);
      toast?.(`commit stubbed (${changes.length} change${changes.length === 1 ? '' : 's'})`);
    },
    [toast],
  );

  return { listTopologies, getTopology, getServices, getNextIp, getNextSubnet, commit };
}
