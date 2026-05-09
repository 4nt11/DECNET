import { useCallback, useEffect, useState } from 'react';
import api from '../../utils/api';
import { extractErrorDetail } from './helpers';
import type { WebhookRow, WebhookSavePayload } from './types';

export interface MutationResult<T = void> {
  ok: boolean;
  /** populated only on failure; already user-friendly. */
  reason?: string;
  data?: T;
}

export interface CreatedWebhook {
  name: string;
  /** Plaintext secret returned only on POST; never on subsequent GETs. */
  secret?: string;
}

export interface TestResult {
  delivered: boolean;
  status_code?: number;
  error?: string;
}

export interface UseWebhooks {
  webhooks: WebhookRow[];
  loading: boolean;
  error: string | null;
  reload: () => Promise<void>;
  createWebhook: (payload: WebhookSavePayload) => Promise<MutationResult<CreatedWebhook>>;
  updateWebhook: (uuid: string, payload: WebhookSavePayload) => Promise<MutationResult>;
  removeWebhook: (uuid: string) => Promise<MutationResult>;
  testWebhook: (uuid: string) => Promise<MutationResult<TestResult>>;
}

/** Owns the webhooks list and CRUD round-trips. UI concerns
 *  (toasts, modal state, selection) stay in the page; the hook
 *  speaks `{ ok, reason }` so callers can announce however they
 *  like without leaking axios error shapes upward. */
export function useWebhooks(): UseWebhooks {
  const [webhooks, setWebhooks] = useState<WebhookRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const res = await api.get<WebhookRow[]>('/webhooks/');
      setWebhooks(res.data);
      setError(null);
    } catch (err) {
      setError(extractErrorDetail(err, 'Failed to load webhooks'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void reload(); }, [reload]);

  const createWebhook = useCallback(
    async (payload: WebhookSavePayload): Promise<MutationResult<CreatedWebhook>> => {
      try {
        const res = await api.post<CreatedWebhook>('/webhooks/', payload);
        await reload();
        return { ok: true, data: res.data };
      } catch (err) {
        return { ok: false, reason: extractErrorDetail(err, 'Save failed') };
      }
    },
    [reload],
  );

  const updateWebhook = useCallback(
    async (uuid: string, payload: WebhookSavePayload): Promise<MutationResult> => {
      try {
        await api.patch(`/webhooks/${uuid}`, payload);
        await reload();
        return { ok: true };
      } catch (err) {
        return { ok: false, reason: extractErrorDetail(err, 'Save failed') };
      }
    },
    [reload],
  );

  const removeWebhook = useCallback(
    async (uuid: string): Promise<MutationResult> => {
      try {
        await api.delete(`/webhooks/${uuid}`);
        await reload();
        return { ok: true };
      } catch (err) {
        return { ok: false, reason: extractErrorDetail(err, 'Delete failed') };
      }
    },
    [reload],
  );

  const testWebhook = useCallback(
    async (uuid: string): Promise<MutationResult<TestResult>> => {
      try {
        const res = await api.post<TestResult>(`/webhooks/${uuid}/test`);
        await reload();
        return { ok: true, data: res.data };
      } catch (err) {
        return { ok: false, reason: extractErrorDetail(err, 'Test failed') };
      }
    },
    [reload],
  );

  return { webhooks, loading, error, reload, createWebhook, updateWebhook, removeWebhook, testWebhook };
}
