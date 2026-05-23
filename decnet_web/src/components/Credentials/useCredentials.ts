// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useState } from 'react';
import api from '../../utils/api';
import {
  CREDS_LIMIT, REUSE_LIMIT, REUSE_MAP_CAP, reuseKey,
} from './helpers';
import type {
  CredentialEntry, CredentialReuseRow, ReuseMapEntry, Tab,
} from './types';

export interface UseCredentialsArgs {
  tab: Tab;
  page: number;
  query: string;
  serviceFilter: string;
  /** Bumped by the page to force a refetch of every endpoint. */
  refreshTick: number;
}

export interface UseCredentials {
  creds: CredentialEntry[];
  credsTotal: number;
  reuseRows: CredentialReuseRow[];
  reuseTotal: number;
  reuseMap: Map<string, ReuseMapEntry>;
  loading: boolean;
  /** Fetch a full reuse row by id (used when clicking a reuse badge
   *  on the creds tab — the map only stores enough to show the pill). */
  fetchReuseDetail: (id: string) => Promise<CredentialReuseRow | null>;
}

/** Owns the three credential fetches: the active tab's list (creds or
 *  reuse), and a small reuse-summary map that powers the reuse pill on
 *  the creds row. The page passes URL state in; the hook stays free
 *  of URL/router concerns. */
export function useCredentials(args: UseCredentialsArgs): UseCredentials {
  const { tab, page, query, serviceFilter, refreshTick } = args;

  const [creds, setCreds] = useState<CredentialEntry[]>([]);
  const [credsTotal, setCredsTotal] = useState(0);
  const [reuseRows, setReuseRows] = useState<CredentialReuseRow[]>([]);
  const [reuseTotal, setReuseTotal] = useState(0);
  const [reuseMap, setReuseMap] = useState<Map<string, ReuseMapEntry>>(new Map());
  const [loading, setLoading] = useState(true);

  // ── creds list (CREDS tab only)
  useEffect(() => {
    if (tab !== 'creds') return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const offset = (page - 1) * CREDS_LIMIT;
        let url = `/credentials?limit=${CREDS_LIMIT}&offset=${offset}`;
        if (query) url += `&search=${encodeURIComponent(query)}`;
        if (serviceFilter) url += `&service=${encodeURIComponent(serviceFilter)}`;
        const res = await api.get(url);
        if (cancelled) return;
        setCreds(res.data.data);
        setCredsTotal(res.data.total);
      } catch (err) {
        console.error('Failed to fetch credentials', err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [tab, query, serviceFilter, page, refreshTick]);

  // ── reuse list (REUSE tab only)
  useEffect(() => {
    if (tab !== 'reuse') return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const offset = (page - 1) * REUSE_LIMIT;
        const res = await api.get(`/credential-reuse?limit=${REUSE_LIMIT}&offset=${offset}`);
        if (cancelled) return;
        setReuseRows(res.data.data);
        setReuseTotal(res.data.total);
      } catch (err) {
        console.error('Failed to fetch credential-reuse', err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [tab, page, refreshTick]);

  // ── reuse-map (always; powers the badge column on the CREDS tab)
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await api.get(`/credential-reuse?limit=${REUSE_MAP_CAP}&offset=0`);
        if (cancelled) return;
        const m = new Map<string, ReuseMapEntry>();
        (res.data.data as CredentialReuseRow[]).forEach((r) => {
          m.set(reuseKey(r.secret_sha256, r.secret_kind, r.principal), {
            id: r.id, target_count: r.target_count,
          });
        });
        setReuseMap(m);
      } catch {
        /* badge column degrades silently to "—" */
      }
    })();
    return () => { cancelled = true; };
  }, [refreshTick]);

  const fetchReuseDetail = useCallback(
    async (id: string): Promise<CredentialReuseRow | null> => {
      try {
        const res = await api.get(`/credential-reuse/${id}`);
        return res.data as CredentialReuseRow;
      } catch (err) {
        console.error('Failed to fetch reuse detail', err);
        return null;
      }
    },
    [],
  );

  return {
    creds, credsTotal, reuseRows, reuseTotal, reuseMap, loading, fetchReuseDetail,
  };
}
