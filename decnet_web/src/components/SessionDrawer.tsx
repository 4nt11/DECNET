import React, { useEffect, useRef, useState } from 'react';
import { X, AlertTriangle } from 'lucide-react';
import api from '../utils/api';
import { useEscapeKey } from '../hooks/useEscapeKey';
import { useFocusTrap } from '../hooks/useFocusTrap';
// @ts-expect-error -- ships without type defs; 3.x CJS build is used directly
import * as AsciinemaPlayer from 'asciinema-player';
import 'asciinema-player/dist/bundle/asciinema-player.css';

interface SessionDrawerProps {
  decky: string;
  sid: string;
  fields: Record<string, any>;
  onClose: () => void;
}

interface TranscriptPage {
  sid: string;
  service: string;
  header: Record<string, any>;
  events: [number, string, string][];
  offset: number;
  limit: number;
  total: number;
  has_more: boolean;
  truncated: boolean;
}

const PAGE_SIZE = 500;

const Row: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div style={{ display: 'flex', gap: '12px', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
    <div style={{ minWidth: '140px', color: 'var(--dim-color)', fontSize: '0.75rem', textTransform: 'uppercase' }}>{label}</div>
    <div style={{ flex: 1, fontSize: '0.85rem', wordBreak: 'break-all' }}>{value ?? <span style={{ opacity: 0.4 }}>—</span>}</div>
  </div>
);

function buildCastBlob(header: Record<string, any>, events: [number, string, string][]): string {
  const headerLine = JSON.stringify({
    version: 2,
    width: header.width ?? 80,
    height: header.height ?? 24,
    timestamp: header.timestamp,
    env: header.env,
  });
  const eventLines = events.map(([t, ch, d]) => JSON.stringify([t, ch, d]));
  return [headerLine, ...eventLines].join('\n') + '\n';
}

const SessionDrawer: React.FC<SessionDrawerProps> = ({ decky, sid, fields, onClose }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEscapeKey(onClose, true);
  useFocusTrap(panelRef, true);
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, []);

  const [header, setHeader] = useState<Record<string, any> | null>(null);
  const [events, setEvents] = useState<[number, string, string][]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);
  const playerContainer = useRef<HTMLDivElement | null>(null);
  const playerInstance = useRef<any>(null);

  useEffect(() => {
    let cancelled = false;
    const fetchAll = async () => {
      setLoading(true);
      setError(null);
      let offset = 0;
      let hdr: Record<string, any> | null = null;
      const allEvents: [number, string, string][] = [];
      let truncFlag = false;
      try {
        // eslint-disable-next-line no-constant-condition
        while (true) {
          const res = await api.get<TranscriptPage>(
            `/transcripts/${encodeURIComponent(decky)}/${encodeURIComponent(sid)}`,
            { params: { offset, limit: PAGE_SIZE } },
          );
          if (cancelled) return;
          if (!hdr) hdr = res.data.header;
          truncFlag = truncFlag || res.data.truncated;
          allEvents.push(...res.data.events);
          if (offset === 0) {
            setHeader(hdr);
            setEvents([...allEvents]);
            setLoading(false);
          } else {
            setEvents([...allEvents]);
          }
          if (!res.data.has_more) break;
          offset += PAGE_SIZE;
          setLoadingMore(true);
        }
        setTruncated(truncFlag);
        setLoadingMore(false);
      } catch (err: any) {
        if (cancelled) return;
        const status = err?.response?.status;
        setError(
          status === 403 ? 'Admin role required to view transcripts.' :
          status === 404 ? 'Transcript not found (shard may have rotated).' :
          'Failed to load transcript — see console.'
        );
        console.error('transcript fetch failed', err);
        setLoading(false);
      }
    };
    fetchAll();
    return () => { cancelled = true; };
  }, [decky, sid]);

  // Re-mount the player whenever the event window grows. asciinema-player
  // doesn't expose a public feed() API in v3, so we rebuild from the full
  // in-memory cast each time — cheap for v1-scale sessions (≤ 10 MB cap).
  //
  // Pass the cast as {data: ...} directly rather than a Blob URL. The
  // URL path silently fails when the browser's fetch for the blob races
  // the createObjectURL revoke, or when the mime-type guess trips the
  // player's loader — either way the user gets a play button that does
  // nothing on click. Inline data skips the whole fetch detour.
  useEffect(() => {
    if (!header || !playerContainer.current) return;
    // Asciicast v2 ch values: "o" (output), "i" (input), "r" (resize).
    // Drop anything else so a stray malformed line can't derail parsing.
    const playable = events.filter(([, ch]) => ch === 'o' || ch === 'i' || ch === 'r');
    if (playable.length === 0) return;

    if (playerInstance.current) {
      try { playerInstance.current.dispose(); } catch { /* ignore */ }
      playerInstance.current = null;
    }
    const cast = buildCastBlob(header, playable);
    // One-time diagnostic: when the player silently refuses to play, the
    // cast text itself is usually the culprit. Log the first chunk so
    // "yes, the header renders correctly" is a one-F12 check.
    console.debug(
      'asciinema cast (first 400 chars):',
      cast.slice(0, 400),
      `| events=${playable.length} | cols=${header.width} rows=${header.height}`,
    );
    try {
      const p = AsciinemaPlayer.create(
        { data: cast },
        playerContainer.current,
        { fit: 'width', terminalFontSize: '12px' },
      );
      playerInstance.current = p;
      // The player's init() is async; any failure there bypasses the
      // sync try/catch above and lands as an unhandled rejection.
      // Hook every lifecycle event so we can see which state it
      // actually ends up in ("loading" / "ended" / "errored" / etc).
      for (const evt of ['ready', 'play', 'pause', 'ended', 'error', 'errored', 'loading']) {
        try {
          p.addEventListener?.(evt, (...args: unknown[]) =>
            console.debug(`asciinema-player event: ${evt}`, ...args),
          );
        } catch { /* addEventListener may not support this event name */ }
      }
      // getDuration() resolves once the recording is parsed. If it
      // resolves to 0 or NaN we know the parser produced an empty
      // events stream despite the cast looking well-formed.
      p.getDuration?.().then(
        (d: number) => console.debug('asciinema-player duration:', d),
        (err: unknown) => console.error('asciinema-player getDuration failed:', err),
      );
    } catch (err) {
      console.error('asciinema-player failed to mount (sync):', err);
    }
    return () => {
      if (playerInstance.current) {
        try { playerInstance.current.dispose(); } catch { /* ignore */ }
        playerInstance.current = null;
      }
    };
  }, [header, events]);

  const service = fields.service;
  const srcIp = fields.src_ip;
  const duration = fields.duration_s;
  const bytes = fields.bytes;

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0,
        backgroundColor: 'rgba(0,0,0,0.6)',
        display: 'flex', justifyContent: 'flex-end',
        zIndex: 1000,
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 'min(920px, 100%)', height: '100%',
          backgroundColor: 'var(--bg-color, #0d1117)',
          borderLeft: '1px solid var(--border-color, #30363d)',
          padding: '24px', overflowY: 'auto',
          color: 'var(--text-color)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', letterSpacing: '0.1em' }}>
              SESSION TRANSCRIPT · {decky}
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 'bold', marginTop: '4px', fontFamily: 'monospace' }}>
              {sid}
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-color)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {truncated && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            padding: '8px 12px', marginBottom: '16px',
            border: '1px solid rgba(255, 170, 0, 0.3)',
            backgroundColor: 'rgba(255, 170, 0, 0.05)',
            fontSize: '0.75rem', color: '#ffaa00',
          }}>
            <AlertTriangle size={14} />
            Session exceeded 10 MB cap — playback is truncated.
          </div>
        )}

        {error && (
          <div style={{ color: '#ff5555', fontSize: '0.8rem', marginBottom: '16px' }}>{error}</div>
        )}

        <section style={{ marginBottom: '16px' }}>
          <div ref={playerContainer} style={{ background: '#000', minHeight: '340px' }} />
          {loading && <div style={{ opacity: 0.5, fontSize: '0.75rem', marginTop: '8px' }}>LOADING TRANSCRIPT…</div>}
          {loadingMore && <div style={{ opacity: 0.5, fontSize: '0.75rem', marginTop: '8px' }}>loading more events…</div>}
        </section>

        <section>
          <h3 style={{ fontSize: '0.8rem', letterSpacing: '0.1em', color: 'var(--dim-color)', marginBottom: '8px' }}>
            METADATA
          </h3>
          <Row label="Service" value={service} />
          <Row label="Src IP" value={srcIp} />
          <Row label="Duration" value={duration ? `${duration}s` : null} />
          <Row label="Bytes" value={bytes ? `${bytes}` : null} />
          <Row label="Events" value={events.length} />
        </section>
      </div>
    </div>
  );
};

export default SessionDrawer;
