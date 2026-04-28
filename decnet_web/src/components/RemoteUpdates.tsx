import React, { useEffect, useState } from 'react';
import api from '../utils/api';
import EmptyState from './EmptyState/EmptyState';
import './Dashboard.css';
import {
  Upload, RefreshCw, RotateCcw, Package, AlertTriangle, CheckCircle,
  Wifi, WifiOff, Server,
} from '../icons';

interface HostRelease {
  host_uuid: string;
  host_name: string;
  address: string;
  reachable: boolean;
  agent_status?: string | null;
  current_sha?: string | null;
  previous_sha?: string | null;
  releases: Array<Record<string, any>>;
  detail?: string | null;
}

interface PushResult {
  host_uuid: string;
  host_name: string;
  status: 'updated' | 'rolled-back' | 'failed' | 'self-updated' | 'self-failed';
  http_status?: number | null;
  sha?: string | null;
  detail?: string | null;
  stderr?: string | null;
}

interface Toast {
  id: number;
  kind: 'success' | 'warn' | 'error';
  text: string;
}

const shortSha = (s: string | null | undefined): string => (s ? s.slice(0, 7) : '—');

const RemoteUpdates: React.FC = () => {
  const [hosts, setHosts] = useState<HostRelease[]>([]);
  const [loading, setLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);
  const [busyRow, setBusyRow] = useState<string | null>(null);
  const [fleetBusy, setFleetBusy] = useState(false);
  const [showFleetModal, setShowFleetModal] = useState(false);
  const [includeSelf, setIncludeSelf] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const pushToast = (kind: Toast['kind'], text: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 7000);
  };

  const fetchHosts = async () => {
    try {
      const res = await api.get('/swarm-updates/hosts');
      setHosts(res.data.hosts || []);
    } catch (err: any) {
      if (err.response?.status !== 403) console.error('Failed to fetch host releases', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchRole = async () => {
    try {
      const res = await api.get('/config');
      setIsAdmin(res.data.role === 'admin');
    } catch {
      setIsAdmin(false);
    }
  };

  useEffect(() => {
    fetchRole();
    fetchHosts();
    const interval = setInterval(fetchHosts, 10000);
    return () => clearInterval(interval);
  }, []);

  const describeResult = (r: PushResult): Toast => {
    const sha = shortSha(r.sha);
    switch (r.status) {
      case 'updated':
        return { id: 0, kind: 'success', text: `${r.host_name} → updated (sha ${sha})` };
      case 'self-updated':
        return { id: 0, kind: 'success', text: `${r.host_name} → updater upgraded (sha ${sha})` };
      case 'rolled-back':
        return { id: 0, kind: 'warn', text: `${r.host_name} → rolled back: ${r.detail || r.stderr || 'probe failed'}` };
      case 'failed':
        return { id: 0, kind: 'error', text: `${r.host_name} → failed: ${r.detail || 'transport error'}` };
      case 'self-failed':
        return { id: 0, kind: 'error', text: `${r.host_name} → updater push failed: ${r.detail || 'unknown'}` };
    }
  };

  const handlePush = async (host: HostRelease, kind: 'agent' | 'self') => {
    setBusyRow(host.host_uuid);
    const endpoint = kind === 'agent' ? '/swarm-updates/push' : '/swarm-updates/push-self';
    try {
      const res = await api.post(endpoint, { host_uuids: [host.host_uuid] }, { timeout: 240000 });
      (res.data.results as PushResult[]).forEach((r) => {
        const t = describeResult(r);
        pushToast(t.kind, t.text);
      });
      await fetchHosts();
    } catch (err: any) {
      pushToast('error', `${host.host_name} → request failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setBusyRow(null);
    }
  };

  const handleRollback = async (host: HostRelease) => {
    if (!window.confirm(`Roll back ${host.host_name} to its previous release?`)) return;
    setBusyRow(host.host_uuid);
    try {
      const res = await api.post('/swarm-updates/rollback', { host_uuid: host.host_uuid }, { timeout: 60000 });
      const r = res.data as PushResult & { status: 'rolled-back' | 'failed' };
      if (r.status === 'rolled-back') {
        pushToast('success', `${host.host_name} → rolled back`);
      } else {
        pushToast('error', `${host.host_name} → rollback failed: ${r.detail || 'unknown'}`);
      }
      await fetchHosts();
    } catch (err: any) {
      pushToast('error', `${host.host_name} → rollback failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setBusyRow(null);
    }
  };

  const handleFleetPush = async () => {
    setFleetBusy(true);
    setShowFleetModal(false);
    try {
      const res = await api.post(
        '/swarm-updates/push',
        { all: true, include_self: includeSelf },
        { timeout: 600000 },
      );
      (res.data.results as PushResult[]).forEach((r) => {
        const t = describeResult(r);
        pushToast(t.kind, t.text);
      });
      await fetchHosts();
    } catch (err: any) {
      pushToast('error', `Fleet push failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setFleetBusy(false);
    }
  };

  if (loading) return <div className="loader">QUERYING WORKER UPDATER FLEET...</div>;

  if (!isAdmin) {
    return (
      <div className="dashboard">
        <div style={{ padding: '24px', color: 'var(--dim-color)' }}>
          <AlertTriangle size={20} style={{ verticalAlign: 'middle' }} /> Admin role required for Remote Updates.
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard swarm-root">
      <div className="page-header">
        <div className="page-title-group">
          <h1><Package size={18} /> REMOTE UPDATES</h1>
          <span className="page-sub">
            push updater bundles to enrolled workers · {hosts.length} WORKER{hosts.length === 1 ? '' : 'S'}
          </span>
        </div>
        <button
          onClick={() => setShowFleetModal(true)}
          disabled={fleetBusy || hosts.length === 0}
          className="control-btn primary"
        >
          {fleetBusy ? <RefreshCw size={14} className="spin" /> : <Upload size={14} />}
          {fleetBusy ? 'PUSHING…' : 'PUSH TO ALL'}
        </button>
      </div>

      {showFleetModal && (
        <div
          style={{
            marginBottom: '24px', padding: '24px',
            backgroundColor: 'var(--secondary-color)', border: '1px solid var(--accent-color)',
          }}
        >
          <h3 style={{ marginTop: 0 }}>Push current tree to every enrolled worker</h3>
          <p style={{ color: 'var(--dim-color)', fontSize: '0.85rem' }}>
            A tarball of the master's working tree will be uploaded to each worker's updater,
            installed, and the agent will be restarted. Failed probes auto-roll-back.
          </p>
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: '16px 0' }}>
            <input type="checkbox" checked={includeSelf} onChange={(e) => setIncludeSelf(e.target.checked)} />
            Also upgrade the updater itself (<code>--include-self</code>)
          </label>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
            <button onClick={() => setShowFleetModal(false)} style={{ border: '1px solid var(--border-color)', color: 'var(--dim-color)' }}>
              CANCEL
            </button>
            <button
              onClick={handleFleetPush}
              style={{ background: 'var(--accent-color)', color: '#000', border: 'none' }}
            >
              CONFIRM FLEET PUSH
            </button>
          </div>
        </div>
      )}

      {hosts.length === 0 ? (
        <EmptyState
          icon={Server}
          title="NO UPDATER-ENABLED WORKERS"
          hint="run `decnet swarm enroll --host <name> --updater` to add one"
        />
      ) : (
        <div style={{ display: 'grid', gap: '16px' }}>
          {hosts.map((h) => {
            const busy = busyRow === h.host_uuid;
            return (
              <div
                key={h.host_uuid}
                className="stat-card"
                style={{
                  flexDirection: 'column', alignItems: 'stretch',
                  padding: '20px', gap: '12px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    {h.reachable ? <Wifi size={16} style={{ color: 'var(--accent-color)' }} />
                                 : <WifiOff size={16} style={{ color: 'var(--danger-color, #f88)' }} />}
                    <span className="matrix-text" style={{ fontSize: '1.1rem', fontWeight: 'bold' }}>{h.host_name}</span>
                    <span className="dim" style={{ fontSize: '0.8rem' }}>{h.address}</span>
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      onClick={() => handlePush(h, 'agent')}
                      disabled={busy || !h.reachable}
                      style={{ display: 'flex', alignItems: 'center', gap: '6px', border: '1px solid var(--accent-color)', color: 'var(--accent-color)' }}
                    >
                      {busy ? <RefreshCw size={12} className="spin" /> : <Upload size={12} />}
                      PUSH
                    </button>
                    <button
                      onClick={() => handlePush(h, 'self')}
                      disabled={busy || !h.reachable}
                      style={{ display: 'flex', alignItems: 'center', gap: '6px', border: '1px solid var(--highlight-color)', color: 'var(--highlight-color)' }}
                    >
                      {busy ? <RefreshCw size={12} className="spin" /> : <Package size={12} />}
                      UPDATER
                    </button>
                    <button
                      onClick={() => handleRollback(h)}
                      disabled={busy || !h.reachable || !h.previous_sha}
                      style={{ display: 'flex', alignItems: 'center', gap: '6px', border: '1px solid var(--border-color)', color: 'var(--dim-color)' }}
                      title={h.previous_sha ? 'Roll back to previous release' : 'No previous release on worker'}
                    >
                      <RotateCcw size={12} /> ROLLBACK
                    </button>
                  </div>
                </div>
                {h.reachable ? (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
                    <Info label="CURRENT" value={shortSha(h.current_sha)} tone="accent" />
                    <Info label="PREVIOUS" value={shortSha(h.previous_sha)} tone="dim" />
                    <Info label="AGENT" value={h.agent_status || 'unknown'} tone={h.agent_status === 'ok' ? 'accent' : 'dim'} />
                  </div>
                ) : (
                  <div style={{ color: 'var(--dim-color)', fontSize: '0.85rem' }}>
                    UNREACHABLE — {h.detail || 'no response'}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      <div style={{ position: 'fixed', bottom: '24px', right: '24px', display: 'flex', flexDirection: 'column', gap: '8px', zIndex: 1000 }}>
        {toasts.map((t) => (
          <div
            key={t.id}
            style={{
              padding: '12px 16px',
              backgroundColor: 'var(--secondary-color)',
              border: `1px solid ${t.kind === 'success' ? 'var(--accent-color)' : t.kind === 'warn' ? 'var(--highlight-color)' : 'var(--danger-color, #f88)'}`,
              color: t.kind === 'success' ? 'var(--accent-color)' : t.kind === 'warn' ? 'var(--highlight-color)' : 'var(--danger-color, #f88)',
              fontSize: '0.85rem', maxWidth: '420px', boxShadow: '0 2px 8px rgba(0,0,0,0.4)',
              display: 'flex', alignItems: 'center', gap: '8px',
            }}
          >
            {t.kind === 'success' ? <CheckCircle size={14} /> : <AlertTriangle size={14} />}
            {t.text}
          </div>
        ))}
      </div>
    </div>
  );
};

const Info: React.FC<{ label: string; value: string; tone: 'accent' | 'dim' }> = ({ label, value, tone }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
    <span className="dim" style={{ fontSize: '0.75rem' }}>{label}</span>
    <span
      style={{
        color: tone === 'accent' ? 'var(--accent-color)' : 'var(--text-color)',
        fontFamily: 'monospace', fontSize: '0.9rem',
      }}
    >
      {value}
    </span>
  </div>
);

export default RemoteUpdates;
