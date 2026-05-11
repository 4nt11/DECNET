import { useCallback, useEffect, useState } from 'react';
import api from '../../utils/api';
import { extractErrorDetail } from './helpers';
import type { BundleRequest, BundleResult, SwarmHost } from './types';

export type MutationResult<T = void> = T extends void
  ? { ok: true } | { ok: false; reason: string }
  : { ok: true; data: T } | { ok: false; reason: string };

export interface UseSwarmHosts {
  hosts: SwarmHost[];
  loading: boolean;
  error: string | null;
  reload: () => Promise<void>;
  teardownHost: (uuid: string) => Promise<MutationResult>;
  decommissionHost: (uuid: string) => Promise<MutationResult>;
  generateBundle: (req: BundleRequest) => Promise<MutationResult<BundleResult>>;
}

const POLL_INTERVAL_MS = 10_000;

/** Owns the swarm-host list with a 10s heartbeat poll plus the
 *  teardown / decommission / enroll-bundle round-trips. UI concerns
 *  (arm-then-confirm, busy spinners, modal toggling) stay in the page;
 *  the hook returns `{ ok, reason }` so callers can decide whether to
 *  toast, alert, or set local error UI. */
export function useSwarmHosts(): UseSwarmHosts {
  const [hosts, setHosts] = useState<SwarmHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const res = await api.get<SwarmHost[]>('/swarm/hosts');
      setHosts(res.data);
      setError(null);
    } catch (err) {
      setError(extractErrorDetail(err, 'Failed to fetch swarm hosts'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
    const t = setInterval(reload, POLL_INTERVAL_MS);
    return () => clearInterval(t);
  }, [reload]);

  const teardownHost = useCallback(
    async (uuid: string): Promise<MutationResult> => {
      try {
        // 202 Accepted — teardown runs async on the backend.
        await api.post(`/swarm/hosts/${uuid}/teardown`, {});
        await reload();
        return { ok: true };
      } catch (err) {
        return { ok: false, reason: extractErrorDetail(err, 'Teardown failed') };
      }
    },
    [reload],
  );

  const decommissionHost = useCallback(
    async (uuid: string): Promise<MutationResult> => {
      try {
        await api.delete(`/swarm/hosts/${uuid}`);
        await reload();
        return { ok: true };
      } catch (err) {
        return { ok: false, reason: extractErrorDetail(err, 'Decommission failed') };
      }
    },
    [reload],
  );

  const generateBundle = useCallback(
    async (req: BundleRequest): Promise<MutationResult<BundleResult>> => {
      try {
        const res = await api.post<BundleResult>('/swarm/enroll-bundle', req);
        await reload();
        return { ok: true, data: res.data };
      } catch (err) {
        return { ok: false, reason: extractErrorDetail(err, 'Enrollment bundle creation failed') };
      }
    },
    [reload],
  );

  return { hosts, loading, error, reload, teardownHost, decommissionHost, generateBundle };
}
