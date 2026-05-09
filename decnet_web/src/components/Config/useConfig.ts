import { useCallback, useEffect, useMemo, useState } from 'react';
import api from '../../utils/api';
import type { ConfigData } from './types';

/** Discriminated result shape used by every Config mutation. The
 *  Config tabs translate this into the inline FormMsg chip — keeps
 *  the hook free of UI concerns. */
export type ConfigMutationResult =
  | { ok: true }
  | { ok: false; reason: string };

export interface ReinitTotals {
  logs: number;
  bounties: number;
  attackers: number;
}

export type ReinitResult =
  | { ok: true; deleted: ReinitTotals }
  | { ok: false; reason: string };

export interface UseConfigResult {
  config: ConfigData | null;
  loading: boolean;
  isAdmin: boolean;
  reload: () => Promise<void>;

  // Settings
  setDeploymentLimit: (n: number) => Promise<ConfigMutationResult>;
  setGlobalMutationInterval: (s: string) => Promise<ConfigMutationResult>;

  // Users
  addUser: (input: {
    username: string;
    password: string;
    role: 'admin' | 'viewer';
  }) => Promise<ConfigMutationResult>;
  deleteUser: (uuid: string) => Promise<ConfigMutationResult>;
  setUserRole: (uuid: string, role: string) => Promise<ConfigMutationResult>;
  resetUserPassword: (uuid: string, newPassword: string) => Promise<ConfigMutationResult>;

  // Danger zone
  reinit: () => Promise<ReinitResult>;
}

const errMsg = (err: unknown, fallback: string): string => {
  const e = err as { response?: { data?: { detail?: string } } };
  return e?.response?.data?.detail || fallback;
};

/** Owns the GET /config fetch and all admin mutations. Mutation
 *  results carry their own error string so callers can render an
 *  inline FormMsg without re-parsing axios errors. */
export function useConfig(): UseConfigResult {
  const [config, setConfig] = useState<ConfigData | null>(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    try {
      const res = await api.get('/config');
      setConfig(res.data);
    } catch (err) {
      console.error('Failed to fetch config', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void reload(); }, [reload]);

  const setDeploymentLimit = useCallback(
    async (n: number): Promise<ConfigMutationResult> => {
      try {
        await api.put('/config/deployment-limit', { deployment_limit: n });
        await reload();
        return { ok: true };
      } catch (err) {
        return { ok: false, reason: errMsg(err, 'UPDATE FAILED') };
      }
    },
    [reload],
  );

  const setGlobalMutationInterval = useCallback(
    async (s: string): Promise<ConfigMutationResult> => {
      try {
        await api.put('/config/global-mutation-interval', { global_mutation_interval: s });
        await reload();
        return { ok: true };
      } catch (err) {
        return { ok: false, reason: errMsg(err, 'UPDATE FAILED') };
      }
    },
    [reload],
  );

  const addUser = useCallback(
    async (input: {
      username: string;
      password: string;
      role: 'admin' | 'viewer';
    }): Promise<ConfigMutationResult> => {
      try {
        await api.post('/config/users', input);
        await reload();
        return { ok: true };
      } catch (err) {
        return { ok: false, reason: errMsg(err, 'CREATE FAILED') };
      }
    },
    [reload],
  );

  const deleteUser = useCallback(
    async (uuid: string): Promise<ConfigMutationResult> => {
      try {
        await api.delete(`/config/users/${uuid}`);
        await reload();
        return { ok: true };
      } catch (err) {
        return { ok: false, reason: errMsg(err, 'Delete failed') };
      }
    },
    [reload],
  );

  const setUserRole = useCallback(
    async (uuid: string, role: string): Promise<ConfigMutationResult> => {
      try {
        await api.put(`/config/users/${uuid}/role`, { role });
        await reload();
        return { ok: true };
      } catch (err) {
        return { ok: false, reason: errMsg(err, 'Role update failed') };
      }
    },
    [reload],
  );

  const resetUserPassword = useCallback(
    async (uuid: string, newPassword: string): Promise<ConfigMutationResult> => {
      try {
        await api.put(`/config/users/${uuid}/reset-password`, { new_password: newPassword });
        await reload();
        return { ok: true };
      } catch (err) {
        return { ok: false, reason: errMsg(err, 'Password reset failed') };
      }
    },
    [reload],
  );

  const reinit = useCallback(async (): Promise<ReinitResult> => {
    try {
      const res = await api.delete('/config/reinit');
      const deleted = res.data?.deleted as ReinitTotals;
      return { ok: true, deleted };
    } catch (err) {
      return { ok: false, reason: errMsg(err, 'REINIT FAILED') };
    }
  }, []);

  const isAdmin = config?.role === 'admin';

  return useMemo(
    () => ({
      config, loading, isAdmin, reload,
      setDeploymentLimit, setGlobalMutationInterval,
      addUser, deleteUser, setUserRole, resetUserPassword,
      reinit,
    }),
    [
      config, loading, isAdmin, reload,
      setDeploymentLimit, setGlobalMutationInterval,
      addUser, deleteUser, setUserRole, resetUserPassword,
      reinit,
    ],
  );
}
