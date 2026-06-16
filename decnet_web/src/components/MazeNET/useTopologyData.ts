// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react';
import type { ApiError } from '../../utils/api';
import type { Net, MazeNode, Edge } from './types';
import { DEFAULT_SERVICES, ARCHETYPES as DEFAULT_ARCHETYPES } from './data';
import type { Archetype, ServiceDef } from './data';
import type { MazeApi } from './useMazeApi';
import { MutationFailedError } from './useTopologyEditor';
import { useTopologyStream, type TopologyStreamEvent } from './useTopologyStream';

export interface TopoMeta {
  status: string;
  name: string;
  version: number;
  targetHost: string | null;
  mode: string;
}

const EMPTY_META: TopoMeta = {
  status: 'pending',
  name: '',
  version: 0,
  targetHost: null,
  mode: 'unihost',
};

export interface UseTopologyDataResult {
  // Canvas data
  nets: Net[];
  setNets: React.Dispatch<React.SetStateAction<Net[]>>;
  nodes: MazeNode[];
  setNodes: React.Dispatch<React.SetStateAction<MazeNode[]>>;
  edges: Edge[];
  setEdges: React.Dispatch<React.SetStateAction<Edge[]>>;

  // Topology metadata snapshot
  topoMeta: TopoMeta;

  // Catalogs
  services: ServiceDef[];
  archetypes: Archetype[];

  // Errors + transient banners
  loadErr: string | null;
  actionErr: string | null;
  /** Persistent (no auto-clear) error from a failed live mutation —
   *  the topology likely went degraded. Dismissed via clearCommitErr. */
  commitErr: string | null;
  clearCommitErr: () => void;
  flashErr: (err: unknown, fallback: string) => void;

  // Deploy
  deploying: boolean;
  onDeploy: () => Promise<void>;

  // Live stream
  streamLive: boolean;
  lastEventAt: Date | null;
  streamEnabled: boolean;

  // Actions
  refetch: () => Promise<void>;
}

/** Owns every read/write side of the MazeNET canvas data plane:
 *  the topology hydrate, the services + archetypes catalog, the
 *  deploy POST, and the live-mutation SSE stream. State setters
 *  for nets / nodes / edges are exposed because the per-operation
 *  callbacks living in the page need to optimistically patch
 *  local state alongside their REST calls. */
export function useTopologyData(
  api: MazeApi,
  topologyId: string,
): UseTopologyDataResult {
  const [nets, setNets] = useState<Net[]>([]);
  const [nodes, setNodes] = useState<MazeNode[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [topoMeta, setTopoMeta] = useState<TopoMeta>(EMPTY_META);

  const [services, setServices] = useState<ServiceDef[]>(DEFAULT_SERVICES);
  const [archetypes, setArchetypes] = useState<Archetype[]>(DEFAULT_ARCHETYPES);

  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [commitErr, setCommitErr] = useState<string | null>(null);
  const [deploying, setDeploying] = useState(false);

  const clearCommitErr = useCallback(() => setCommitErr(null), []);

  const flashErr = useCallback((err: unknown, fallback: string) => {
    // A failed live mutation is loud + persistent: the queue halted and
    // the topology probably degraded — don't let it vanish in 4s.
    if (err instanceof MutationFailedError) {
      setCommitErr(err.message);
      return;
    }
    const msg = (err as ApiError)?.response?.data?.detail ?? (err as ApiError)?.message ?? fallback;
    setActionErr(msg);
    setTimeout(() => setActionErr(null), 4000);
  }, []);

  // Catalogs — fetched once on mount with bundled fallback.
  useEffect(() => {
    let cancelled = false;
    api.getServices().then((s) => { if (!cancelled) setServices(s); }).catch(() => {});
    api.getArchetypes().then((a) => { if (!cancelled) setArchetypes(a); }).catch(() => {});
    return () => { cancelled = true; };
  }, [api]);

  const refetch = useCallback(async () => {
    if (!topologyId) return;
    try {
      const h = await api.getTopology(topologyId);
      setNets(h.nets);
      setNodes(h.nodes);
      setEdges(h.edges);
      setTopoMeta({
        status: h.topology.status,
        name: h.topology.name,
        version: h.topology.version,
        targetHost: h.topology.target_host_uuid ?? null,
        mode: h.topology.mode ?? 'unihost',
      });
      setLoadErr(null);
    } catch (err) {
      setLoadErr((err as Error)?.message ?? 'topology load failed');
    }
  }, [api, topologyId]);

  useEffect(() => { void refetch(); }, [refetch]);

  // Live topology stream — only open when the topology is deployed;
  // pending topologies have no mutator loop.
  const [streamLive, setStreamLive] = useState(false);
  const [lastEventAt, setLastEventAt] = useState<Date | null>(null);
  const streamEnabled = topoMeta.status === 'active' || topoMeta.status === 'degraded';

  const onStreamEvent = useCallback((event: TopologyStreamEvent) => {
    if (event.name === 'snapshot'
      || event.name.startsWith('mutation.')
      || event.name === 'status') {
      setStreamLive(true);
      setLastEventAt(new Date());
    }
    if (event.name === 'mutation.failed') {
      const p = event.payload ?? {};
      const reason = typeof p.reason === 'string' ? p.reason
        : typeof p.error === 'string' ? p.error
        : 'mutation failed — check mutator logs';
      setActionErr(`mutation failed: ${reason}`);
      setTimeout(() => setActionErr(null), 6000);
    }
    if (event.name === 'mutation.applied'
      || event.name === 'mutation.failed'
      || event.name === 'status') {
      void refetch();
    }
    // Live service mutations from another tab / admin: optimistically
    // patch local state so the chip set reflects shape without a full
    // re-hydrate. The post-mutation services list lives on the payload;
    // same shape the actor's POST/DELETE response carries.
    if (event.name === 'decky.service_added'
      || event.name === 'decky.service_removed') {
      const p = event.payload ?? {};
      const deckyName = typeof p.decky_name === 'string' ? p.decky_name : null;
      const services = Array.isArray(p.services) ? p.services as string[] : null;
      if (deckyName && services) {
        setNodes((prev) => prev.map((n) => n.kind === 'decky' && n.name === deckyName
          ? { ...n, services } : n));
        setStreamLive(true);
        setLastEventAt(new Date());
      }
    }
  }, [refetch]);

  const onStreamError = useCallback(() => { setStreamLive(false); }, []);

  useTopologyStream({
    topologyId: streamEnabled ? topologyId : null,
    enabled: streamEnabled,
    onEvent: onStreamEvent,
    onError: onStreamError,
  });

  useEffect(() => { if (!streamEnabled) setStreamLive(false); }, [streamEnabled]);

  const onDeploy = useCallback(async () => {
    if (!topologyId) return;
    setDeploying(true);
    try {
      await api.deployTopology(topologyId);
      await refetch();
    } catch (err) {
      flashErr(err, 'deploy failed');
    } finally {
      setDeploying(false);
    }
  }, [api, topologyId, flashErr, refetch]);

  return {
    nets, setNets,
    nodes, setNodes,
    edges, setEdges,
    topoMeta,
    services, archetypes,
    loadErr, actionErr, commitErr, clearCommitErr, flashErr,
    deploying, onDeploy,
    streamLive, lastEventAt, streamEnabled,
    refetch,
  };
}
