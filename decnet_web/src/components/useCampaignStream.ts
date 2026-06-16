// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Campaign-clustering event stream — opens an SSE connection to
 * `/campaigns/events` and dispatches typed events to the caller.
 *
 * Mirror of `useIdentityStream` for the layer above. CampaignDetail
 * subscribes to refresh its own row + linked-identity list when
 * `campaign.identity.assigned` / `campaign.merged` / `campaign.unmerged`
 * fires.
 */
import { useEffect, useRef } from 'react';
import { mintSseTicket } from '../utils/sseTicket';

export type CampaignStreamEventName =
  | 'snapshot'
  | 'formed'
  | 'identity.assigned'
  | 'merged'
  | 'unmerged';

export interface CampaignStreamEvent {
  name: CampaignStreamEventName | string;
  topic?: string;
  type?: string;
  ts?: string;
  payload: Record<string, unknown>;
}

export interface UseCampaignStreamOptions {
  enabled: boolean;
  onEvent: (event: CampaignStreamEvent) => void;
  onError?: () => void;
}

const NAMED_EVENTS: CampaignStreamEventName[] = [
  'snapshot',
  'formed',
  'identity.assigned',
  'merged',
  'unmerged',
];

export function useCampaignStream({
  enabled,
  onEvent,
  onError,
}: UseCampaignStreamOptions): void {
  const esRef = useRef<EventSource | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onEventRef = useRef(onEvent);
  const onErrorRef = useRef(onError);
  useEffect(() => { onEventRef.current = onEvent; }, [onEvent]);
  useEffect(() => { onErrorRef.current = onError; }, [onError]);

  useEffect(() => {
    if (!enabled) return;

    let cancelled = false;

    const connect = async () => {
      if (esRef.current) esRef.current.close();

      let ticket: string;
      try {
        ticket = await mintSseTicket();
      } catch {
        onErrorRef.current?.();
        if (!cancelled) {
          reconnectRef.current = setTimeout(connect, 3000);
        }
        return;
      }
      if (cancelled) return;

      const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
      const url = `${baseUrl}/campaigns/events?ticket=${encodeURIComponent(ticket)}`;

      const es = new EventSource(url);
      esRef.current = es;

      const dispatch = (name: string) => (event: MessageEvent) => {
        try {
          const parsed = JSON.parse(event.data) as Partial<CampaignStreamEvent>;
          onEventRef.current({
            name,
            topic: parsed.topic,
            type: parsed.type,
            ts: parsed.ts,
            payload: (parsed.payload ?? {}) as Record<string, unknown>,
          });
        } catch (err) {
          console.error('useCampaignStream: parse failed', err);
        }
      };

      for (const name of NAMED_EVENTS) {
        es.addEventListener(name, dispatch(name) as EventListener);
      }

      es.onerror = () => {
        es.close();
        esRef.current = null;
        onErrorRef.current?.();
        if (!cancelled) {
          reconnectRef.current = setTimeout(connect, 3000);
        }
      };
    };

    connect();

    return () => {
      cancelled = true;
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      if (esRef.current) esRef.current.close();
      esRef.current = null;
    };
  }, [enabled]);
}
