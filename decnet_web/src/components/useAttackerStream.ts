/**
 * Per-attacker behavioural event stream — opens an SSE connection to
 * `/attackers/{uuid}/events` and dispatches typed events to the caller.
 *
 * Mirrors `useIdentityStream` (reconnect on error after 3s, callbacks
 * stashed in refs so the connection isn't torn down on every consumer
 * rerender). Unlike the identity stream's broad firehose, this hook
 * is scoped to ONE attacker — the backend per-attacker filter keys on
 * `payload.attacker_uuid` so consumers only receive their attacker's
 * events.
 *
 * Event names emitted by the backend (`_sse_name_for` in
 * `decnet/web/router/attackers/api_events.py`):
 *
 *   * `snapshot`            — one-shot, fires immediately on connect
 *                             with `{attacker_uuid, observations: [...]}`.
 *   * `observation`         — every `attacker.observation.<primitive>`
 *                             event collapses to this single name; the
 *                             primitive rides in `payload.primitive`.
 *   * `fingerprint.rotated` — `attacker.fingerprint_rotated`.
 *   * `attacker.scored`     — score-threshold crossings.
 */
import { useEffect, useRef } from 'react';

export interface ObservationFrame {
  primitive: string;
  value: unknown;
  confidence: number;
  ts?: number;
  source?: string;
  attacker_uuid?: string;
}

export interface SnapshotFrame {
  attacker_uuid: string;
  observations: ObservationFrame[];
}

export type AttackerStreamEventName =
  | 'snapshot'
  | 'observation'
  | 'fingerprint.rotated'
  | 'attacker.scored';

export interface AttackerStreamEvent {
  name: AttackerStreamEventName | string;
  topic?: string;
  type?: string;
  ts?: string;
  payload: Record<string, unknown>;
}

export interface UseAttackerStreamOptions {
  attackerUuid: string;
  enabled: boolean;
  onSnapshot?: (data: SnapshotFrame) => void;
  onObservation?: (data: ObservationFrame) => void;
  onFingerprintRotated?: (data: Record<string, unknown>) => void;
  onScored?: (data: Record<string, unknown>) => void;
  onError?: () => void;
}

const NAMED_EVENTS: AttackerStreamEventName[] = [
  'snapshot',
  'observation',
  'fingerprint.rotated',
  'attacker.scored',
];

const RECONNECT_MS = 3000;

export function useAttackerStream({
  attackerUuid,
  enabled,
  onSnapshot,
  onObservation,
  onFingerprintRotated,
  onScored,
  onError,
}: UseAttackerStreamOptions): void {
  const esRef = useRef<EventSource | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onSnapshotRef = useRef(onSnapshot);
  const onObservationRef = useRef(onObservation);
  const onFingerprintRotatedRef = useRef(onFingerprintRotated);
  const onScoredRef = useRef(onScored);
  const onErrorRef = useRef(onError);
  useEffect(() => { onSnapshotRef.current = onSnapshot; }, [onSnapshot]);
  useEffect(() => { onObservationRef.current = onObservation; }, [onObservation]);
  useEffect(() => { onFingerprintRotatedRef.current = onFingerprintRotated; }, [onFingerprintRotated]);
  useEffect(() => { onScoredRef.current = onScored; }, [onScored]);
  useEffect(() => { onErrorRef.current = onError; }, [onError]);

  useEffect(() => {
    if (!enabled || !attackerUuid) return;

    const connect = () => {
      if (esRef.current) esRef.current.close();
      const token = localStorage.getItem('token') ?? '';
      const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
      const url = `${baseUrl}/attackers/${encodeURIComponent(attackerUuid)}/events?token=${encodeURIComponent(token)}`;

      const es = new EventSource(url);
      esRef.current = es;

      const handle = (name: string) => (event: MessageEvent) => {
        let parsed: AttackerStreamEvent;
        try {
          parsed = JSON.parse(event.data) as AttackerStreamEvent;
        } catch (err) {
          console.error('useAttackerStream: parse failed', err);
          return;
        }
        const payload = (parsed.payload ?? parsed) as Record<string, unknown>;
        switch (name) {
          case 'snapshot':
            onSnapshotRef.current?.(payload as unknown as SnapshotFrame);
            break;
          case 'observation':
            onObservationRef.current?.(payload as unknown as ObservationFrame);
            break;
          case 'fingerprint.rotated':
            onFingerprintRotatedRef.current?.(payload);
            break;
          case 'attacker.scored':
            onScoredRef.current?.(payload);
            break;
        }
      };

      for (const name of NAMED_EVENTS) {
        es.addEventListener(name, handle(name) as EventListener);
      }

      es.onerror = () => {
        es.close();
        esRef.current = null;
        onErrorRef.current?.();
        reconnectRef.current = setTimeout(connect, RECONNECT_MS);
      };
    };

    connect();

    return () => {
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      if (esRef.current) esRef.current.close();
      esRef.current = null;
    };
  }, [enabled, attackerUuid]);
}
