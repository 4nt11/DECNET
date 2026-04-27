/**
 * Orchestrator event stream — opens an SSE connection to
 * `/orchestrator/events/stream` and dispatches typed events to the
 * caller. Mirror of `useCampaignStream`.
 */
import { useEffect, useRef } from 'react';

export type OrchestratorStreamEventName = 'snapshot' | 'traffic' | 'file';

export interface OrchestratorStreamEvent {
  name: OrchestratorStreamEventName | string;
  topic?: string;
  type?: string;
  ts?: string;
  payload: Record<string, unknown>;
}

export interface UseOrchestratorStreamOptions {
  enabled: boolean;
  onEvent: (event: OrchestratorStreamEvent) => void;
  onStatus?: (status: 'connecting' | 'live' | 'error') => void;
}

const NAMED_EVENTS: OrchestratorStreamEventName[] = ['snapshot', 'traffic', 'file'];

export function useOrchestratorStream({
  enabled,
  onEvent,
  onStatus,
}: UseOrchestratorStreamOptions): void {
  const esRef = useRef<EventSource | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onEventRef = useRef(onEvent);
  const onStatusRef = useRef(onStatus);
  useEffect(() => { onEventRef.current = onEvent; }, [onEvent]);
  useEffect(() => { onStatusRef.current = onStatus; }, [onStatus]);

  useEffect(() => {
    if (!enabled) return;

    const connect = () => {
      if (esRef.current) esRef.current.close();
      onStatusRef.current?.('connecting');
      const token = localStorage.getItem('token') ?? '';
      const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
      const url = `${baseUrl}/orchestrator/events/stream?token=${encodeURIComponent(token)}`;

      const es = new EventSource(url);
      esRef.current = es;

      es.onopen = () => onStatusRef.current?.('live');

      const dispatch = (name: string) => (event: MessageEvent) => {
        try {
          const parsed = JSON.parse(event.data) as Partial<OrchestratorStreamEvent>;
          onEventRef.current({
            name,
            topic: parsed.topic,
            type: parsed.type,
            ts: parsed.ts,
            payload: (parsed.payload ?? {}) as Record<string, unknown>,
          });
        } catch (err) {
          console.error('useOrchestratorStream: parse failed', err);
        }
      };

      for (const name of NAMED_EVENTS) {
        es.addEventListener(name, dispatch(name) as EventListener);
      }

      es.onerror = () => {
        es.close();
        esRef.current = null;
        onStatusRef.current?.('error');
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
