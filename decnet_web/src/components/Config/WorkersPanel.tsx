// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from 'react';
import { AlertTriangle, Play, RefreshCw, Square } from '../../icons';
import api from '../../utils/api';
import { useToast } from '../Toasts/useToast';

// Pollster view backed by GET /workers. Every 5s we pull the full snapshot;
// the registry is cheap (in-memory dict) so there's no need for SSE here.

interface WorkerStatusRow {
  name: string;
  status: 'ok' | 'stale' | 'unknown';
  last_heartbeat_ts: number | null;
  seconds_since: number | null;
  extra: Record<string, unknown>;
  installed: boolean;
}

interface Props {
  pushToast: ReturnType<typeof useToast>['push'];
}

// Renders the LLM status of a realism-emitting worker (today: orchestrator).
// Sourced from the heartbeat ``extra.realism`` payload published by
// :func:`decnet.orchestrator.worker._realism_health_snapshot`.
const RealismBadge: React.FC<{
  realism: {
    llm_enabled?: boolean;
    llm_backend?: string | null;
    llm_model?: string | null;
    llm_breaker_state?: 'closed' | 'open' | 'half_open' | null;
  };
}> = ({ realism }) => {
  if (!realism.llm_enabled) {
    return (
      <span
        className="chip dim-chip"
        style={{ marginLeft: 8 }}
        title="LLM enrichment disabled (DECNET_REALISM_LLM unset or --no-llm)"
      >
        LLM OFF
      </span>
    );
  }
  const breaker = realism.llm_breaker_state ?? 'closed';
  const breakerColor =
    breaker === 'open' ? '#ff5555'
    : breaker === 'half_open' ? 'var(--warn)'
    : 'var(--matrix)';
  const tooltip = [
    `Backend: ${realism.llm_backend ?? '?'}`,
    realism.llm_model ? `Model: ${realism.llm_model}` : null,
    `Circuit breaker: ${breaker}`,
  ].filter(Boolean).join('\n');
  return (
    <span
      className="chip dim-chip"
      style={{ marginLeft: 8, display: 'inline-flex', alignItems: 'center', gap: 4 }}
      title={tooltip}
    >
      <span style={{
        display: 'inline-block', width: 6, height: 6, borderRadius: '50%',
        backgroundColor: breakerColor,
      }} />
      LLM {(realism.llm_backend ?? 'on').toUpperCase()}
    </span>
  );
};

export const WorkersPanel: React.FC<Props> = ({ pushToast }) => {
  const [workers, setWorkers] = useState<WorkerStatusRow[] | null>(null);
  const [busConnected, setBusConnected] = useState<boolean | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [stopping, setStopping] = useState<Record<string, boolean>>({});
  const [starting, setStarting] = useState<Record<string, boolean>>({});
  const [startingAll, setStartingAll] = useState(false);

  const fetchWorkers = async () => {
    try {
      const res = await api.get('/workers');
      setWorkers(res.data?.workers ?? []);
      setBusConnected(
        typeof res.data?.bus_connected === 'boolean' ? res.data.bus_connected : null,
      );
      setErr(null);
    } catch (e: any) {
      setErr(e?.response?.data?.detail || 'Failed to load workers');
    }
  };

  const [refreshing, setRefreshing] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<number | null>(null);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await fetchWorkers();
      setLastRefresh(Date.now());
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    handleRefresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleStop = async (name: string) => {
    setStopping((s) => ({ ...s, [name]: true }));
    try {
      await api.post(`/workers/${encodeURIComponent(name)}/stop`);
      pushToast({ text: `STOP REQUESTED · ${name.toUpperCase()}`, tone: 'violet', icon: 'terminal' });
      // Kick a refresh sooner than the 5s tick so the UI feels responsive.
      setTimeout(fetchWorkers, 1000);
    } catch (e: any) {
      const detail = e?.response?.data?.detail || 'Stop failed';
      pushToast({ text: `STOP FAILED · ${name.toUpperCase()} — ${detail}`, tone: 'alert', icon: 'alert-triangle' });
    } finally {
      setStopping((s) => ({ ...s, [name]: false }));
    }
  };

  const handleStart = async (name: string) => {
    setStarting((s) => ({ ...s, [name]: true }));
    try {
      await api.post(`/workers/${encodeURIComponent(name)}/start`);
      pushToast({ text: `START REQUESTED · ${name.toUpperCase()}`, tone: 'violet', icon: 'terminal' });
      setTimeout(fetchWorkers, 1500);
      // Auto-clear the spinner state after 15s if the heartbeat still
      // hasn't flipped the row — keeps the UI from getting stuck.
      setTimeout(() => setStarting((s) => ({ ...s, [name]: false })), 15000);
    } catch (e: any) {
      const detail = e?.response?.data?.detail || 'Start failed';
      pushToast({ text: `START FAILED · ${name.toUpperCase()} — ${detail}`, tone: 'alert', icon: 'alert-triangle' });
      setStarting((s) => ({ ...s, [name]: false }));
    }
  };

  const handleStartAll = async () => {
    setStartingAll(true);
    try {
      const res = await api.post('/workers/start-all');
      const started: string[] = res.data?.started ?? [];
      const already: string[] = res.data?.already_running ?? [];
      const failed: Array<{ name: string; reason: string }> = res.data?.failed ?? [];
      const firstFail = failed[0];
      const suffix = firstFail ? ` (first failure: ${firstFail.name} — ${firstFail.reason})` : '';
      pushToast({
        text: `STARTED · ${started.length} · ALREADY RUNNING · ${already.length} · FAILED · ${failed.length}${suffix}`,
        tone: failed.length > 0 ? 'alert' : 'violet',
        icon: failed.length > 0 ? 'alert-triangle' : 'terminal',
      });
      setTimeout(fetchWorkers, 1500);
    } catch (e: any) {
      const detail = e?.response?.data?.detail || 'Start-all failed';
      pushToast({ text: `START ALL FAILED — ${detail}`, tone: 'alert', icon: 'alert-triangle' });
    } finally {
      setStartingAll(false);
    }
  };

  const formatLastSeen = (row: WorkerStatusRow): string => {
    if (row.seconds_since == null) return '—';
    const s = row.seconds_since;
    if (s < 60) return `${Math.floor(s)}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    return `${Math.floor(s / 3600)}h ago`;
  };

  const dotClass = (status: WorkerStatusRow['status']) => {
    if (status === 'ok') return 'status-dot active';
    if (status === 'stale') return 'status-dot warn';
    return 'status-dot idle';
  };

  if (err) {
    return (
      <div className="config-panel">
        <div style={{ padding: '20px', opacity: 0.7 }}>
          <AlertTriangle size={14} style={{ marginRight: 8, verticalAlign: 'middle' }} />
          {err}
        </div>
      </div>
    );
  }

  if (workers === null) {
    return (
      <div className="config-panel">
        <div style={{ padding: '20px', opacity: 0.5 }}>LOADING…</div>
      </div>
    );
  }

  const busOffline = busConnected === false;

  return (
    <div className="config-panel">
      {busOffline && (
        <div
          style={{
            margin: '16px 20px 0',
            padding: '10px 14px',
            border: '1px solid #ffaa00',
            background: 'var(--warn-tint-10)',
            color: 'var(--warn)',
            fontSize: '0.72rem',
            letterSpacing: 1,
            lineHeight: 1.5,
            display: 'flex',
            alignItems: 'flex-start',
            gap: 10,
          }}
        >
          <AlertTriangle size={14} style={{ marginTop: 2, flexShrink: 0 }} />
          <div>
            <div style={{ fontWeight: 700 }}>BUS OFFLINE — heartbeats cannot be received.</div>
            <div style={{ opacity: 0.85, marginTop: 2 }}>
              Start with <code>decnet bus</code> (restart the API if it was up first).
            </div>
          </div>
        </div>
      )}
      <div
        style={{
          padding: '16px 20px 8px',
          fontSize: '0.7rem',
          letterSpacing: '1.5px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
        }}
      >
        <div style={{ opacity: 0.6 }}>
          HEARTBEATS EVERY 30s · <span style={{ color: 'var(--matrix)' }}>OK</span> &lt; 90s · STALE AFTER
          {lastRefresh != null && (
            <span style={{ marginLeft: 10, opacity: 0.7 }}>
              · REFRESHED {new Date(lastRefresh).toLocaleTimeString()}
            </span>
          )}
        </div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <button
            className="action-btn"
            disabled={startingAll}
            onClick={handleStartAll}
            style={{
              padding: '4px 10px',
              fontSize: '0.68rem',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              cursor: startingAll ? 'wait' : 'pointer',
              opacity: startingAll ? 0.6 : 1,
            }}
            title="Start every installed worker unit via systemd (best-effort)"
          >
            <Play size={11} />
            {startingAll ? 'STARTING…' : 'START ALL WORKERS'}
          </button>
          <button
            className="action-btn"
            onClick={handleRefresh}
            disabled={refreshing}
            style={{
              padding: '4px 10px',
              fontSize: '0.68rem',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              cursor: refreshing ? 'wait' : 'pointer',
              opacity: refreshing ? 0.6 : 1,
            }}
            title="Fetch current worker status"
          >
            <RefreshCw
              size={11}
              style={{
                animation: refreshing ? 'spin 0.8s linear infinite' : undefined,
              }}
            />
            REFRESH
          </button>
        </div>
      </div>
      <table className="logs-table" style={{ margin: 0, opacity: busOffline ? 0.45 : 1 }}>
        <thead>
          <tr>
            <th style={{ width: 36 }}></th>
            <th>NAME</th>
            <th>STATUS</th>
            <th>LAST SEEN</th>
            <th style={{ textAlign: 'right' }}>ACTIONS</th>
          </tr>
        </thead>
        <tbody>
          {workers.map((w) => {
            const isStopping = !!stopping[w.name];
            const canStop = w.status === 'ok' && !isStopping && !busOffline;
            const realism = (w.extra && (w.extra as any).realism) as
              | {
                  llm_enabled?: boolean;
                  llm_backend?: string | null;
                  llm_model?: string | null;
                  llm_breaker_state?: 'closed' | 'open' | 'half_open' | null;
                }
              | undefined;
            return (
              <tr key={w.name}>
                <td><span className={dotClass(w.status)} /></td>
                <td style={{ fontWeight: 700, letterSpacing: 1 }}>
                  {w.name.toUpperCase()}
                  {realism && <RealismBadge realism={realism} />}
                </td>
                <td style={{
                  color: w.status === 'ok' ? 'var(--matrix)'
                       : w.status === 'stale' ? 'var(--warn)'
                       : 'var(--fg-4)',
                  letterSpacing: 1,
                }}>
                  {w.status.toUpperCase()}
                </td>
                <td style={{ fontVariantNumeric: 'tabular-nums' }}>{formatLastSeen(w)}</td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    className="action-btn"
                    disabled={!canStop}
                    onClick={() => handleStop(w.name)}
                    style={{
                      padding: '4px 10px',
                      fontSize: '0.68rem',
                      marginRight: 6,
                      minWidth: 78,
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: 4,
                      color: canStop ? 'var(--alert)' : 'var(--alert)',
                      borderColor: canStop ? 'var(--alert)' : 'rgba(255, 77, 77, 0.4)',
                      opacity: canStop ? 1 : 0.3,
                      cursor: canStop ? 'pointer' : 'not-allowed',
                    }}
                    title={
                      busOffline
                        ? 'Bus offline — stop requests cannot be delivered'
                        : canStop
                        ? 'Publish stop intent on the bus'
                        : 'Only OK workers can be stopped'
                    }
                  >
                    <Square size={11} />
                    {isStopping ? '...' : 'STOP'}
                  </button>
                  {(() => {
                    const isStarting = !!starting[w.name];
                    const canStart = w.installed && w.status !== 'ok' && !isStarting;
                    const tooltip = !w.installed
                      ? `Unit not installed — deploy decnet-${w.name}.service first.`
                      : w.status === 'ok'
                      ? 'Already running.'
                      : isStarting
                      ? 'Start request in flight…'
                      : 'Start the worker via systemd.';
                    return (
                      <button
                        className="action-btn"
                        disabled={!canStart}
                        onClick={() => handleStart(w.name)}
                        style={{
                          padding: '4px 10px',
                          fontSize: '0.68rem',
                          minWidth: 78,
                          display: 'inline-flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          gap: 4,
                          opacity: canStart ? 1 : 0.3,
                          cursor: canStart ? 'pointer' : 'not-allowed',
                        }}
                        title={tooltip}
                      >
                        <Play size={11} />
                        {isStarting ? '...' : 'START'}
                      </button>
                    );
                  })()}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
