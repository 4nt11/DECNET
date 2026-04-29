/**
 * Topology event stream — opens an SSE connection to
 * `/topologies/{id}/events` and dispatches typed events to the caller.
 *
 * Mirrors the reconnect shape used by the dashboard's `/stream` consumer:
 * on any error we close the current EventSource and retry after 3s.  The
 * hook is inert until `topologyId` is non-empty and `enabled` is true —
 * typical usage is to gate on `topoStatus === 'active' || 'degraded'` so
 * pending topologies don't open a useless channel.
 */
import { useEffect, useRef } from 'react';

export type TopologyStreamEventName =
  | 'snapshot'
  | 'mutation.enqueued'
  | 'mutation.applying'
  | 'mutation.applied'
  | 'mutation.failed'
  | 'status'
  // Live per-decky service mutations forwarded by the SSE proxy on the
  // server.  The payload carries decky_name + service_name + the
  // post-mutation services list, so a second tab can reconcile shape
  // without a refetch.
  | 'decky.service_added'
  | 'decky.service_removed';

export interface TopologyStreamEvent {
  name: TopologyStreamEventName | string;
  topic?: string;
  type?: string;
  ts?: string;
  payload: Record<string, unknown>;
}

export interface UseTopologyStreamOptions {
  topologyId: string | null;
  enabled: boolean;
  onEvent: (event: TopologyStreamEvent) => void;
  onError?: () => void;
}

const NAMED_EVENTS: TopologyStreamEventName[] = [
  'snapshot',
  'mutation.enqueued',
  'mutation.applying',
  'mutation.applied',
  'mutation.failed',
  'status',
  'decky.service_added',
  'decky.service_removed',
];

export function useTopologyStream({
  topologyId,
  enabled,
  onEvent,
  onError,
}: UseTopologyStreamOptions): void {
  const esRef = useRef<EventSource | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Keep the latest callbacks in refs so reconnect logic doesn't tear
  // down and rebuild the connection every time the consumer rerenders.
  const onEventRef = useRef(onEvent);
  const onErrorRef = useRef(onError);
  useEffect(() => { onEventRef.current = onEvent; }, [onEvent]);
  useEffect(() => { onErrorRef.current = onError; }, [onError]);

  useEffect(() => {
    if (!enabled || !topologyId) return;

    const connect = () => {
      if (esRef.current) esRef.current.close();
      const token = localStorage.getItem('token') ?? '';
      const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
      const url = `${baseUrl}/topologies/${topologyId}/events?token=${encodeURIComponent(token)}`;

      const es = new EventSource(url);
      esRef.current = es;

      const dispatch = (name: string) => (event: MessageEvent) => {
        try {
          const parsed = JSON.parse(event.data) as Partial<TopologyStreamEvent>;
          onEventRef.current({
            name,
            topic: parsed.topic,
            type: parsed.type,
            ts: parsed.ts,
            payload: (parsed.payload ?? {}) as Record<string, unknown>,
          });
        } catch (err) {
          console.error('useTopologyStream: parse failed', err);
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
  }, [topologyId, enabled]);
}
