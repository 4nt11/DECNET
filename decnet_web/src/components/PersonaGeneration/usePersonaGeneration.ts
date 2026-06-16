// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react';
import api from '../../utils/api';
import { extractErrorDetail } from './helpers';
import type { EmailPersona, PersonasResponse } from './types';

export interface PersistResult {
  ok: boolean;
  /** populated only on failure; already user-friendly. */
  reason?: string;
}

export interface UsePersonaGeneration {
  personas: EmailPersona[];
  path: string;
  topoName: string;
  languageDefault: string;
  loading: boolean;
  error: string | null;
  setError: (s: string | null) => void;
  reload: () => Promise<void>;
  persistPersonas: (next: EmailPersona[]) => Promise<PersistResult>;
}

/** Owns the GET/PUT pair for the persona list. The endpoint flips
 *  between the global pool and a topology-bound list based on the
 *  optional topologyId — both share the same wire shape. The hook
 *  returns the discriminated `{ ok, reason }` result so the page
 *  can decide what to toast without leaking axios into the UI. */
export function usePersonaGeneration(topologyId?: string): UsePersonaGeneration {
  const endpoint = topologyId
    ? `/topologies/${topologyId}/personas`
    : '/realism/personas';

  const [personas, setPersonas] = useState<EmailPersona[]>([]);
  const [path, setPath] = useState('');
  const [topoName, setTopoName] = useState('');
  const [languageDefault, setLanguageDefault] = useState('en');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<PersonasResponse>(endpoint);
      setPersonas(res.data.personas ?? []);
      setPath(res.data.path ?? '');
      setTopoName(res.data.topology_name ?? '');
      setLanguageDefault(res.data.language_default ?? 'en');
    } catch (err) {
      setError(extractErrorDetail(err, 'Failed to load personas'));
    } finally {
      setLoading(false);
    }
  }, [endpoint]);

  useEffect(() => { void reload(); }, [reload]);

  const persistPersonas = useCallback(
    async (next: EmailPersona[]): Promise<PersistResult> => {
      setError(null);
      try {
        const res = await api.put<PersonasResponse>(endpoint, { personas: next });
        setPersonas(res.data.personas ?? []);
        setPath(res.data.path ?? '');
        setTopoName(res.data.topology_name ?? '');
        setLanguageDefault(res.data.language_default ?? 'en');
        return { ok: true };
      } catch (err) {
        const msg = extractErrorDetail(err, 'Failed to save personas');
        setError(msg);
        return { ok: false, reason: msg };
      }
    },
    [endpoint],
  );

  return {
    personas, path, topoName, languageDefault, loading, error, setError,
    reload, persistPersonas,
  };
}
