import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  ChevronLeft, ChevronRight, Filter, Cpu, AlertTriangle,
} from '../icons';
import api from '../utils/api';
import EmptyState from './EmptyState/EmptyState';
import { useOrchestratorStream, type OrchestratorStreamEvent } from './useOrchestratorStream';
import './Dashboard.css';

interface OrchestratorEntry {
  uuid: string;
  ts: string;
  kind: 'traffic' | 'file' | string;
  protocol: string;
  action: string;
  src_decky_uuid: string | null;
  dst_decky_uuid: string;
  success: boolean;
  payload: string;
}

type KindFilter = 'all' | 'traffic' | 'file';
type StreamStatus = 'connecting' | 'live' | 'error';

const ROW_CAP = 500;
const HOUR_MS = 60 * 60 * 1000;

const timeAgo = (dateStr: string | null): string => {
  if (!dateStr) return '—';
  const diff = Date.now() - new Date(dateStr).getTime();
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
};

const Orchestrator: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const page = parseInt(searchParams.get('page') || '1');
  const kindParam = (searchParams.get('kind') || 'all') as KindFilter;

  const [rows, setRows] = useState<OrchestratorEntry[]>([]);
  const [streamRows, setStreamRows] = useState<OrchestratorEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<StreamStatus>('connecting');
  const [paused, setPaused] = useState(false);

  const limit = 50;
  const pausedRef = useRef(paused);
  useEffect(() => { pausedRef.current = paused; }, [paused]);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * limit;
      const kindQ = kindParam !== 'all' ? `&kind=${kindParam}` : '';
      const res = await api.get(`/orchestrator/events?limit=${limit}&offset=${offset}${kindQ}`);
      setRows(res.data.data ?? []);
      setTotal(res.data.total ?? 0);
    } catch (err) {
      console.error('Failed to fetch orchestrator events', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchEvents(); }, [page, kindParam]);

  useOrchestratorStream({
    enabled: true,
    onStatus: setStatus,
    onEvent: (ev: OrchestratorStreamEvent) => {
      if (pausedRef.current) return;
      if (ev.name === 'snapshot') return;
      if (ev.name !== 'traffic' && ev.name !== 'file') return;
      const p = ev.payload as Partial<OrchestratorEntry>;
      const row: OrchestratorEntry = {
        uuid: `live-${ev.ts ?? Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        ts: ev.ts ?? new Date().toISOString(),
        kind: (p.kind ?? ev.name) as OrchestratorEntry['kind'],
        protocol: p.protocol ?? '?',
        action: p.action ?? '',
        src_decky_uuid: p.src_decky_uuid ?? null,
        dst_decky_uuid: p.dst_decky_uuid ?? '',
        success: Boolean(p.success),
        payload: typeof p.payload === 'string' ? p.payload : JSON.stringify(p.payload ?? {}),
      };
      setStreamRows((prev) => [row, ...prev].slice(0, ROW_CAP));
    },
  });

  const setPage = (p: number) =>
    setSearchParams({ kind: kindParam, page: p.toString() });
  const setKind = (k: KindFilter) =>
    setSearchParams({ kind: k, page: '1' });

  const totalPages = Math.max(1, Math.ceil(total / limit));

  const visible = useMemo(() => {
    const merged = [...streamRows, ...rows];
    if (kindParam === 'all') return merged;
    return merged.filter((r) => r.kind === kindParam);
  }, [streamRows, rows, kindParam]);

  const failuresLastHour = useMemo(() => {
    const cutoff = Date.now() - HOUR_MS;
    return [...streamRows, ...rows].filter(
      (r) => !r.success && new Date(r.ts).getTime() >= cutoff,
    ).length;
  }, [streamRows, rows]);

  const statusPill = (
    <span className={`chip ${status === 'live' ? 'success-chip' : 'dim-chip'}`}>
      {status === 'live' ? '● LIVE' : status === 'connecting' ? '● CONNECTING' : '● OFFLINE'}
    </span>
  );

  return (
    <div className="bounty-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Cpu size={22} className="violet-accent" />
            <h1>ORCHESTRATOR</h1>
            {statusPill}
            {failuresLastHour > 0 && (
              <span className="chip" style={{ background: 'rgba(220,60,60,0.18)', color: '#ff6e6e' }}>
                <AlertTriangle size={12} /> {failuresLastHour} FAILURES / 1h
              </span>
            )}
          </div>
          <span className="page-sub">
            {total.toLocaleString()} EVENTS · LIFE-INJECTION ACTIVITY
          </span>
        </div>
      </div>

      <div className="controls-row" style={{ gap: 8 }}>
        <button
          className={`chip ${kindParam === 'all' ? 'success-chip' : 'dim-chip'}`}
          onClick={() => setKind('all')}
        >ALL</button>
        <button
          className={`chip ${kindParam === 'traffic' ? 'success-chip' : 'dim-chip'}`}
          onClick={() => setKind('traffic')}
        >TRAFFIC</button>
        <button
          className={`chip ${kindParam === 'file' ? 'success-chip' : 'dim-chip'}`}
          onClick={() => setKind('file')}
        >FILE</button>
        <span style={{ flex: 1 }} />
        <button
          className={`chip ${paused ? 'dim-chip' : 'success-chip'}`}
          onClick={() => setPaused((v) => !v)}
        >{paused ? '▶ RESUME' : '⏸ PAUSE'}</button>
      </div>

      <div className="logs-section">
        <div className="section-header">
          <div className="section-title">
            <Filter size={14} />
            <span>{visible.length.toLocaleString()} EVENTS SHOWN</span>
          </div>
          <div className="section-actions">
            <div className="pager">
              <span className="dim">Page {page} of {totalPages}</span>
              <button disabled={page <= 1} onClick={() => setPage(page - 1)} aria-label="Previous page">
                <ChevronLeft size={14} />
              </button>
              <button disabled={page >= totalPages} onClick={() => setPage(page + 1)} aria-label="Next page">
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        </div>

        <div className="logs-table-container">
          <table className="logs-table">
            <thead>
              <tr>
                <th>TS</th>
                <th>KIND</th>
                <th>ACTION</th>
                <th>SRC → DST</th>
                <th>OK</th>
                <th>PAYLOAD</th>
              </tr>
            </thead>
            <tbody>
              {visible.length > 0 ? visible.map((r) => (
                <tr
                  key={r.uuid}
                  style={!r.success ? { background: 'rgba(220,60,60,0.06)' } : undefined}
                >
                  <td className="dim">{timeAgo(r.ts)}</td>
                  <td>
                    <span className={`chip ${r.kind === 'traffic' ? 'success-chip' : 'dim-chip'}`}>
                      {r.kind.toUpperCase()}
                    </span>
                  </td>
                  <td className="matrix-text" style={{ fontFamily: 'var(--font-mono)' }}>
                    {r.action}
                  </td>
                  <td className="dim" style={{ fontFamily: 'var(--font-mono)' }}>
                    {r.src_decky_uuid ? `${r.src_decky_uuid.slice(0, 8)}…` : '—'}
                    {' → '}
                    {r.dst_decky_uuid ? `${r.dst_decky_uuid.slice(0, 8)}…` : '—'}
                  </td>
                  <td>{r.success ? '✓' : '✗'}</td>
                  <td className="dim" style={{ fontFamily: 'var(--font-mono)', maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.payload}
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={6}>
                    <EmptyState
                      icon={Cpu}
                      title={loading ? 'LOADING…' : 'NO ORCHESTRATOR ACTIVITY YET'}
                      hint={loading ? undefined : 'start the worker with `decnet orchestrate`'}
                    />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Orchestrator;
