/**
 * Identity-resolution event stream — opens an SSE connection to
 * `/identities/events` and dispatches typed events to the caller.
 *
 * Mirrors `useTopologyStream` (reconnect on error after 3s, callbacks
 * stashed in refs so the connection isn't torn down on every consumer
 * rerender). The stream is broadly scoped — every identity event, not
 * per-uuid — because both AttackerDetail and IdentityDetail want the
 * same firehose:
 *
 *   * AttackerDetail watches for `identity.formed` events whose payload
 *     references its observation uuid (the badge appears once the
 *     clusterer binds the row), plus `merged` / `unmerged` so the
 *     badge link updates if the row's identity gets re-pointed.
 *   * IdentityDetail watches for `observation.linked` / `merged` /
 *     `unmerged` against the identity it's rendering.
 *
 * Each consumer applies its own filter inside `onEvent`; the hook
 * itself is dumb glue.
 */
import { useEffect, useRef } from 'react';

export type IdentityStreamEventName =
  | 'snapshot'
  | 'formed'
  | 'observation.linked'
  | 'merged'
  | 'unmerged'
  | 'campaign.assigned';

export interface IdentityStreamEvent {
  name: IdentityStreamEventName | string;
  topic?: string;
  type?: string;
  ts?: string;
  payload: Record<string, unknown>;
}

export interface UseIdentityStreamOptions {
  enabled: boolean;
  onEvent: (event: IdentityStreamEvent) => void;
  onError?: () => void;
}

const NAMED_EVENTS: IdentityStreamEventName[] = [
  'snapshot',
  'formed',
  'observation.linked',
  'merged',
  'unmerged',
  'campaign.assigned',
];

export function useIdentityStream({
  enabled,
  onEvent,
  onError,
}: UseIdentityStreamOptions): void {
  const esRef = useRef<EventSource | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onEventRef = useRef(onEvent);
  const onErrorRef = useRef(onError);
  useEffect(() => { onEventRef.current = onEvent; }, [onEvent]);
  useEffect(() => { onErrorRef.current = onError; }, [onError]);

  useEffect(() => {
    if (!enabled) return;

    const connect = () => {
      if (esRef.current) esRef.current.close();
      const token = localStorage.getItem('token') ?? '';
      const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
      const url = `${baseUrl}/identities/events?token=${encodeURIComponent(token)}`;

      const es = new EventSource(url);
      esRef.current = es;

      const dispatch = (name: string) => (event: MessageEvent) => {
        try {
          const parsed = JSON.parse(event.data) as Partial<IdentityStreamEvent>;
          onEventRef.current({
            name,
            topic: parsed.topic,
            type: parsed.type,
            ts: parsed.ts,
            payload: (parsed.payload ?? {}) as Record<string, unknown>,
          });
        } catch (err) {
          console.error('useIdentityStream: parse failed', err);
        }
      };

      for (const name of NAMED_EVENTS) {
        es.addEventListener(name, dispatch(name) as EventListener);
      }

      es.onerror = () => {
        es.close();
        esRef.current = null;
        onErrorRef.current?.();
        reconnectRef.current = setTimeout(connect, 3000);
      };
    };

    connect();

    return () => {
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      if (esRef.current) esRef.current.close();
      esRef.current = null;
    };
  }, [enabled]);
}
