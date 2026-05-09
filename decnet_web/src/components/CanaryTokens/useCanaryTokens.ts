import { useCallback, useEffect, useMemo, useState } from 'react';
import api from '../../utils/api';
import type { CanaryTokenRow } from '../CanaryTokenDrawer';
import type { BlobRow, DeckyOption, TopologyOption } from './types';
import { extractError } from './helpers';

export type DeleteBlobResult =
  | { ok: true }
  | { ok: false; reason: string };

export interface UseCanaryTokensResult {
  tokens: CanaryTokenRow[];
  blobs: BlobRow[];
  deckies: DeckyOption[];
  topologies: TopologyOption[];
  loading: boolean;
  error: string | null;

  /** Re-fetch all four lists (tokens, blobs, deckies, topologies). */
  reload: () => Promise<void>;

  /** Direct setters for optimistic merges from modals (CreateTokenModal,
   *  UploadModal, drawer revoke). The hook doesn't try to be clever
   *  about this — modals already have the row that came back from the
   *  server, so they just slot it in. */
  prependToken: (t: CanaryTokenRow) => void;
  prependBlob: (b: BlobRow) => void;
  markTokenRevoked: (uuid: string) => void;
  /** DELETE /canary/blobs/:uuid; returns ok=false with the server's
   *  detail string when refused (typically because tokens still
   *  reference the blob). */
  deleteBlob: (uuid: string) => Promise<DeleteBlobResult>;
}

/** Owns the initial parallel fetch of /canary/tokens, /canary/blobs,
 *  /deckies, and /topologies/?status=active, plus the deleteBlob
 *  mutation. The viewer-level 403 on /canary/blobs is silently
 *  tolerated — viewers see an empty blob list rather than an error. */
export function useCanaryTokens(): UseCanaryTokensResult {
  const [tokens, setTokens] = useState<CanaryTokenRow[]>([]);
  const [blobs, setBlobs] = useState<BlobRow[]>([]);
  const [deckies, setDeckies] = useState<DeckyOption[]>([]);
  const [topologies, setTopologies] = useState<TopologyOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [t, b, d, topos] = await Promise.all([
        api.get('/canary/tokens'),
        // Viewers can't list blobs — silently fall back so the
        // tokens tab still renders.
        api.get('/canary/blobs').catch(() => ({ data: { blobs: [] } })),
        api.get<DeckyOption[]>('/deckies').catch(() => ({ data: [] })),
        // Active topologies only — planting on a torn-down or pending
        // topology would 422/404 anyway.  Trailing slash matters:
        // FastAPI's slash-redirect issues a 307 and the browser re-fires
        // without the Authorization header, landing as 401 on the
        // redirected URL. Hit /topologies/ directly.
        api.get('/topologies/?status=active').catch(() => ({ data: { data: [] } })),
      ]);
      setTokens(t.data.tokens || []);
      setBlobs(b.data.blobs || []);
      setDeckies(Array.isArray(d.data) ? d.data : []);
      const topoRows: Array<{ id: string; name: string; status: string }> =
        topos.data?.data ?? [];
      setTopologies(topoRows.map((r) => ({ id: r.id, name: r.name, status: r.status })));
    } catch (err) {
      setError(extractError(err, 'Failed to load canary tokens.'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void reload(); }, [reload]);

  const prependToken = useCallback((t: CanaryTokenRow) => {
    setTokens((prev) => [t, ...prev]);
  }, []);

  const prependBlob = useCallback((b: BlobRow) => {
    setBlobs((prev) => prev.some((x) => x.uuid === b.uuid) ? prev : [b, ...prev]);
  }, []);

  const markTokenRevoked = useCallback((uuid: string) => {
    setTokens((prev) =>
      prev.map((t) => (t.uuid === uuid ? { ...t, state: 'revoked' } : t)),
    );
  }, []);

  const deleteBlob = useCallback(async (uuid: string): Promise<DeleteBlobResult> => {
    try {
      await api.delete(`/canary/blobs/${encodeURIComponent(uuid)}`);
      setBlobs((prev) => prev.filter((b) => b.uuid !== uuid));
      return { ok: true };
    } catch (err) {
      return { ok: false, reason: extractError(err, 'Delete failed.') };
    }
  }, []);

  return useMemo(
    () => ({
      tokens, blobs, deckies, topologies, loading, error,
      reload, prependToken, prependBlob, markTokenRevoked, deleteBlob,
    }),
    [
      tokens, blobs, deckies, topologies, loading, error,
      reload, prependToken, prependBlob, markTokenRevoked, deleteBlob,
    ],
  );
}
