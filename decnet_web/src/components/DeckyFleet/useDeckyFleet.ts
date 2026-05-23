// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useMemo, useState } from 'react';
import api, { type ApiError } from '../../utils/api';
import { ARCHETYPES as FALLBACK_ARCHETYPES } from '../MazeNET/data';
import { archetypeIcon } from './helpers';
import type { Archetype, Decky, SwarmDeckyRaw } from './types';

export interface DeployMode {
  mode: string;
  swarm_host_count: number;
}

export type MutateResult =
  | { ok: true }
  | { ok: false; reason: 'timeout' | 'error' };

export type TeardownResult =
  | { ok: true }
  | { ok: false; reason: string };

export interface UseDeckyFleetResult {
  deckies: Decky[];
  loading: boolean;
  isAdmin: boolean;
  deployMode: DeployMode | null;
  archetypes: Archetype[];
  isSwarm: boolean;

  /** Name of the decky currently mid-mutate, or null when idle. */
  mutating: string | null;
  /** Set of decky names currently mid-teardown. */
  tearingDown: Set<string>;

  /** Re-fetch the decky list under the current deploy mode. */
  refresh: () => Promise<void>;
  /** Force-mutate one decky. Resolves to a discriminated result so
   *  the caller can branch toast tone without seeing axios errors. */
  mutate: (name: string) => Promise<MutateResult>;
  /** Update or clear a decky's periodic mutate interval. */
  setMutateInterval: (name: string, minutes: number | null) => Promise<boolean>;
  /** Tear down a swarm-pinned decky on its host. */
  teardown: (d: Decky) => Promise<TeardownResult>;
  /** Optimistically apply a server-returned services list to a card
   *  (used by DeckyCard's add/remove-service flow). */
  applyServicesChange: (name: string, services: string[]) => void;
}

const POLL_MS = 10_000;

/** Owns every read- and write-side data flow for the DeckyFleet
 *  page: the mode-switched fleet fetch, role lookup, archetype
 *  catalog, mutate / interval / teardown POSTs, and the 10s polling
 *  loop. UI concerns (toasts, arm-confirm, modal visibility) stay
 *  in the consuming page. */
export function useDeckyFleet(): UseDeckyFleetResult {
  const [deckies, setDeckies] = useState<Decky[]>([]);
  const [loading, setLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);
  const [deployMode, setDeployMode] = useState<DeployMode | null>(null);
  const [archetypes, setArchetypes] = useState<Archetype[]>(FALLBACK_ARCHETYPES);
  const [mutating, setMutating] = useState<string | null>(null);
  const [tearingDown, setTearingDown] = useState<Set<string>>(new Set());

  const fetchDeckies = useCallback(async (mode?: string) => {
    try {
      if (mode === 'swarm') {
        const res = await api.get<SwarmDeckyRaw[]>('/swarm/deckies');
        const normalized: Decky[] = res.data.map((s) => ({
          name: s.decky_name,
          ip: s.decky_ip || '—',
          services: s.services || [],
          distro: s.distro || 'unknown',
          hostname: s.hostname || '—',
          archetype: s.archetype,
          service_config: s.service_config || {},
          mutate_interval: s.mutate_interval,
          last_mutated: s.last_mutated || 0,
          swarm: {
            host_uuid: s.host_uuid,
            host_name: s.host_name,
            host_address: s.host_address,
            host_status: s.host_status,
            state: s.state,
            last_error: s.last_error,
            last_seen: s.last_seen,
          },
        }));
        setDeckies(normalized);
      } else {
        const res = await api.get<Decky[]>('/deckies');
        setDeckies(res.data);
      }
    } catch (err) {
      console.error('Failed to fetch decky fleet', err);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchRole = useCallback(async () => {
    try {
      const res = await api.get('/config');
      setIsAdmin(res.data.role === 'admin');
    } catch {
      setIsAdmin(false);
    }
  }, []);

  const fetchDeployMode = useCallback(async (): Promise<string | undefined> => {
    try {
      const res = await api.get('/system/deployment-mode');
      setDeployMode({ mode: res.data.mode, swarm_host_count: res.data.swarm_host_count });
      return res.data.mode as string;
    } catch {
      setDeployMode(null);
      return undefined;
    }
  }, []);

  const fetchArchetypes = useCallback(async () => {
    try {
      const res = await api.get<{ archetypes: { slug: string; display_name: string; services: string[] }[] }>(
        '/topologies/archetypes',
      );
      const list: Archetype[] = res.data.archetypes.map((a) => ({
        slug: a.slug,
        name: a.display_name,
        services: a.services,
        icon: archetypeIcon(a.slug),
      }));
      if (list.length) setArchetypes(list);
    } catch {
      // fall back to bundled list
    }
  }, []);

  const refresh = useCallback(async () => {
    await fetchDeckies(deployMode?.mode);
  }, [fetchDeckies, deployMode]);

  const mutate = useCallback(async (name: string): Promise<MutateResult> => {
    setMutating(name);
    try {
      await api.post(`/deckies/${name}/mutate`, {}, { timeout: 120000 });
      await fetchDeckies(deployMode?.mode);
      return { ok: true };
    } catch (err: unknown) {
      console.error('Failed to mutate', err);
      const e = err as { code?: string };
      return {
        ok: false,
        reason: e.code === 'ECONNABORTED' ? 'timeout' : 'error',
      };
    } finally {
      setMutating(null);
    }
  }, [fetchDeckies, deployMode]);

  const setMutateInterval = useCallback(
    async (name: string, minutes: number | null): Promise<boolean> => {
      try {
        await api.put(`/deckies/${name}/mutate-interval`, { mutate_interval: minutes });
        await fetchDeckies(deployMode?.mode);
        return true;
      } catch (err) {
        console.error('Failed to update interval', err);
        return false;
      }
    },
    [fetchDeckies, deployMode],
  );

  const teardown = useCallback(async (d: Decky): Promise<TeardownResult> => {
    if (!d.swarm) return { ok: false, reason: 'not a swarm decky' };
    setTearingDown((prev) => new Set(prev).add(d.name));
    try {
      await api.post(`/swarm/hosts/${d.swarm.host_uuid}/teardown`, { decky_id: d.name });
      await fetchDeckies(deployMode?.mode);
      return { ok: true };
    } catch (err: unknown) {
      const e = err as ApiError;
      return { ok: false, reason: e?.response?.data?.detail || d.name };
    } finally {
      setTearingDown((prev) => {
        const next = new Set(prev);
        next.delete(d.name);
        return next;
      });
    }
  }, [fetchDeckies, deployMode]);

  const applyServicesChange = useCallback((name: string, services: string[]) => {
    setDeckies((prev) =>
      prev.map((row) => (row.name === name ? { ...row, services } : row)),
    );
  }, []);

  // Initial mount: deploy-mode first (decides which list endpoint to hit),
  // then deckies + role + archetypes in parallel.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const mode = await fetchDeployMode();
      if (cancelled) return;
      await Promise.all([fetchDeckies(mode), fetchRole(), fetchArchetypes()]);
    })();
    const interval = window.setInterval(() => {
      fetchDeployMode().then((m) => fetchDeckies(m));
    }, POLL_MS);
    return () => { cancelled = true; window.clearInterval(interval); };
  }, [fetchDeckies, fetchDeployMode, fetchRole, fetchArchetypes]);

  return useMemo(
    () => ({
      deckies,
      loading,
      isAdmin,
      deployMode,
      archetypes,
      isSwarm: deployMode?.mode === 'swarm',
      mutating,
      tearingDown,
      refresh,
      mutate,
      setMutateInterval,
      teardown,
      applyServicesChange,
    }),
    [
      deckies, loading, isAdmin, deployMode, archetypes,
      mutating, tearingDown,
      refresh, mutate, setMutateInterval, teardown, applyServicesChange,
    ],
  );
}
