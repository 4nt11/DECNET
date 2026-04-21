import { useCallback, useMemo } from 'react';
import api from '../../utils/api';
import { ARCHETYPES as DEFAULT_ARCHETYPES, DEFAULT_SERVICES } from './data';
import type { Archetype, ServiceDef } from './data';
import type { Net, MazeNode, Edge, DeckyNode } from './types';

export interface LANRow {
  id: string;
  topology_id: string;
  name: string;
  subnet: string;
  is_dmz: boolean;
  x?: number | null;
  y?: number | null;
}

export interface DeckyRow {
  uuid: string;
  topology_id: string;
  name: string;
  services: string[];
  decky_config?: Record<string, unknown> | null;
  ip?: string | null;
  state: string;
  x?: number | null;
  y?: number | null;
}

export interface EdgeRow {
  id: string;
  topology_id: string;
  decky_uuid: string;
  lan_id: string;
  is_bridge: boolean;
  forwards_l3: boolean;
}

export interface TopologySummary {
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

export interface HydratedTopology {
  topology: TopologySummary;
  nets: Net[];
  nodes: MazeNode[];
  edges: Edge[];
}

/** Adapt the wire shape to canvas entities. Backend edges are
 *  decky↔LAN membership (bipartite); we surface them as node-in-net
 *  placement. Decky-to-decky traffic edges are derived from
 *  shared-LAN co-membership for visualization only. */
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

  const firstLanFor = new Map<string, string>();
  for (const e of detail.edges) {
    if (!firstLanFor.has(e.decky_uuid)) firstLanFor.set(e.decky_uuid, e.lan_id);
  }

  const nodes: MazeNode[] = detail.deckies.map((d, i): DeckyNode => ({
    kind: 'decky',
    id: d.uuid,
    netId: firstLanFor.get(d.uuid) ?? (nets[0]?.id ?? ''),
    name: d.name,
    archetype: (d.decky_config as { archetype?: string } | null)?.archetype ?? 'linux-server',
    services: d.services,
    status: d.state === 'running' ? 'active' : d.state === 'failed' ? 'hot' : 'idle',
    x: d.x ?? 20 + (i % 2) * 160,
    y: d.y ?? 60 + Math.floor(i / 2) * 90,
    ip: d.ip ?? undefined,
    decky_config: d.decky_config ?? undefined,
  }));

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

interface ArchetypeRow {
  slug: string;
  display_name: string;
  description: string;
  services: string[];
  preferred_distros: string[];
  nmap_os: string;
}

const NMAP_OS_TO_ICON: Record<string, string> = {
  linux: 'server',
  windows: 'monitor',
  embedded: 'cpu',
};

export interface CreateLanBody {
  name: string;
  is_dmz: boolean;
  x: number;
  y: number;
  subnet?: string;
}

export interface CreateDeckyBody {
  name: string;
  services: string[];
  x: number;
  y: number;
  decky_config?: Record<string, unknown>;
}

export interface MazeApi {
  listTopologies:       () => Promise<TopologySummary[]>;
  createBlankTopology:  (name: string) => Promise<TopologySummary>;
  getTopology:          (id: string) => Promise<HydratedTopology>;
  getServices:    () => Promise<ServiceDef[]>;
  getArchetypes:  () => Promise<Archetype[]>;
  getNextIp:      (topologyId: string, lanId: string) => Promise<string>;
  getNextSubnet:  (base?: string) => Promise<string>;

  createLan:   (topologyId: string, body: CreateLanBody) => Promise<LANRow>;
  updateLan:   (topologyId: string, lanId: string, patch: Partial<LANRow>) => Promise<LANRow>;
  deleteLan:   (topologyId: string, lanId: string) => Promise<void>;

  createDecky: (topologyId: string, body: CreateDeckyBody) => Promise<DeckyRow>;
  updateDecky: (topologyId: string, uuid: string, patch: Partial<DeckyRow>) => Promise<DeckyRow>;
  deleteDecky: (topologyId: string, uuid: string) => Promise<void>;

  attachEdge:  (topologyId: string, body: { decky_uuid: string; lan_id: string; is_bridge?: boolean; forwards_l3?: boolean }) => Promise<EdgeRow>;
  detachEdge:  (topologyId: string, edgeId: string) => Promise<void>;

  deployTopology: (topologyId: string) => Promise<void>;
}

export function useMazeApi(): MazeApi {
  const listTopologies = useCallback(async () => {
    const { data } = await api.get('/topologies/');
    return (data?.data ?? []) as TopologySummary[];
  }, []);

  const createBlankTopology = useCallback(async (name: string): Promise<TopologySummary> => {
    const { data } = await api.post<TopologySummary>('/topologies/blank', { name });
    return data;
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

  const getArchetypes = useCallback(async (): Promise<Archetype[]> => {
    try {
      const { data } = await api.get<{ archetypes: ArchetypeRow[] }>('/topologies/archetypes');
      const known = new Map(DEFAULT_ARCHETYPES.map((a) => [a.slug, a.icon]));
      return data.archetypes.map((a) => ({
        slug: a.slug,
        name: a.display_name,
        services: a.services,
        icon: known.get(a.slug) ?? NMAP_OS_TO_ICON[a.nmap_os] ?? 'server',
      }));
    } catch {
      return DEFAULT_ARCHETYPES;
    }
  }, []);

  const getNextIp = useCallback(async (topologyId: string, lanId: string) => {
    const { data } = await api.get<{ subnet: string; ip: string }>(
      `/topologies/${topologyId}/lans/${lanId}/next-ip`,
    );
    return data.ip;
  }, []);

  const getNextSubnet = useCallback(async (base: string = '10.0') => {
    const { data } = await api.get<{ subnet: string }>(
      `/topologies/next-subnet`,
      { params: { base } },
    );
    return data.subnet;
  }, []);

  const createLan = useCallback(
    async (topologyId: string, body: CreateLanBody): Promise<LANRow> => {
      const { data } = await api.post<LANRow>(`/topologies/${topologyId}/lans`, body);
      return data;
    },
    [],
  );

  const updateLan = useCallback(
    async (topologyId: string, lanId: string, patch: Partial<LANRow>): Promise<LANRow> => {
      const { data } = await api.patch<LANRow>(`/topologies/${topologyId}/lans/${lanId}`, patch);
      return data;
    },
    [],
  );

  const deleteLan = useCallback(
    async (topologyId: string, lanId: string): Promise<void> => {
      await api.delete(`/topologies/${topologyId}/lans/${lanId}`);
    },
    [],
  );

  const createDecky = useCallback(
    async (topologyId: string, body: CreateDeckyBody): Promise<DeckyRow> => {
      const { data } = await api.post<DeckyRow>(`/topologies/${topologyId}/deckies`, body);
      return data;
    },
    [],
  );

  const updateDecky = useCallback(
    async (topologyId: string, uuid: string, patch: Partial<DeckyRow>): Promise<DeckyRow> => {
      const { data } = await api.patch<DeckyRow>(
        `/topologies/${topologyId}/deckies/${uuid}`,
        patch,
      );
      return data;
    },
    [],
  );

  const deleteDecky = useCallback(
    async (topologyId: string, uuid: string): Promise<void> => {
      await api.delete(`/topologies/${topologyId}/deckies/${uuid}`);
    },
    [],
  );

  const attachEdge = useCallback(
    async (topologyId: string, body: { decky_uuid: string; lan_id: string; is_bridge?: boolean; forwards_l3?: boolean }): Promise<EdgeRow> => {
      const { data } = await api.post<EdgeRow>(`/topologies/${topologyId}/edges`, body);
      return data;
    },
    [],
  );

  const detachEdge = useCallback(
    async (topologyId: string, edgeId: string): Promise<void> => {
      await api.delete(`/topologies/${topologyId}/edges/${edgeId}`);
    },
    [],
  );

  const deployTopology = useCallback(
    async (topologyId: string): Promise<void> => {
      await api.post(`/topologies/${topologyId}/deploy`, {});
    },
    [],
  );

  return useMemo(
    () => ({
      listTopologies, createBlankTopology, getTopology, getServices, getArchetypes,
      getNextIp, getNextSubnet,
      createLan, updateLan, deleteLan,
      createDecky, updateDecky, deleteDecky,
      attachEdge, detachEdge,
      deployTopology,
    }),
    [
      listTopologies, createBlankTopology, getTopology, getServices, getArchetypes,
      getNextIp, getNextSubnet,
      createLan, updateLan, deleteLan,
      createDecky, updateDecky, deleteDecky,
      attachEdge, detachEdge,
      deployTopology,
    ],
  );
}
