// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react';
import api from '../utils/api';

export type LifecycleStatus = 'pending' | 'running' | 'succeeded' | 'failed';

export interface LifecycleRow {
  id: string;
  decky_name: string;
  host_uuid: string | null;
  operation: 'deploy' | 'mutate';
  status: LifecycleStatus;
  error: string | null;
  started_at: string;
  updated_at: string;
  completed_at: string | null;
}

const TERMINAL = new Set<LifecycleStatus>(['succeeded', 'failed']);

/**
 * Poll ``GET /deckies/lifecycle?ids=…`` every ``intervalMs`` until every
 * row reaches a terminal status.  Returns the latest rows, a derived
 * ``done`` flag, and any HTTP failure that surfaced on the last tick.
 *
 * Polling stops automatically once all rows are terminal (or when
 * ``ids`` becomes empty / unmounts).  Pass an empty array to disable.
 */
export function useLifecyclePolling(
  ids: string[],
  intervalMs: number = 2000,
): { rows: LifecycleRow[]; done: boolean; error: string | null } {
  const [rows, setRows] = useState<LifecycleRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const cancelled = useRef(false);

  useEffect(() => {
    cancelled.current = false;
    if (ids.length === 0) {
      setRows([]);
      return () => { cancelled.current = true; };
    }

    let timer: number | undefined;

    const tick = async () => {
      try {
        const { data } = await api.get<{ rows: LifecycleRow[] }>(
          '/deckies/lifecycle',
          // axios encodes array params as repeated ?ids=… when
          // paramsSerializer isn't overridden — matches FastAPI's expected
          // shape for List[str] Query params.
          { params: { ids }, paramsSerializer: { indexes: null } },
        );
        if (cancelled.current) return;
        const next = data?.rows ?? [];
        setRows(next);
        setError(null);
        const allDone = next.length === ids.length
          && next.every((r) => TERMINAL.has(r.status));
        if (!allDone) {
          timer = window.setTimeout(tick, intervalMs);
        }
      } catch (e: unknown) {
        if (cancelled.current) return;
        const err = e as { message?: string };
        setError(err?.message || 'Lifecycle poll failed');
        timer = window.setTimeout(tick, intervalMs);
      }
    };

    tick();
    return () => {
      cancelled.current = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ids.join('|'), intervalMs]);

  const done = ids.length > 0
    && rows.length === ids.length
    && rows.every((r) => TERMINAL.has(r.status));

  return { rows, done, error };
}
