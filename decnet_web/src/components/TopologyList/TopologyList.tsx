import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Network, Plus, Power, Trash2, UploadCloud, RefreshCw } from 'lucide-react';
import api from '../../utils/api';
import './TopologyList.css';

interface TopologySummary {
  id: string;
  name: string;
  mode: string;
  status: string;
  version: number;
  created_at: string;
  status_changed_at: string | null;
}

interface ListResponse {
  total: number;
  limit: number | null;
  offset: number | null;
  data: TopologySummary[];
}

const statusClass = (s: string): string => {
  switch (s) {
    case 'active':       return 'pill-ok';
    case 'pending':      return 'pill-dim';
    case 'deploying':
    case 'tearing_down': return 'pill-warn';
    case 'degraded':     return 'pill-warn';
    case 'failed':
    case 'teardown_failed': return 'pill-bad';
    case 'torn_down':    return 'pill-dim';
    default: return 'pill-dim';
  }
};

const TopologyList: React.FC = () => {
  const navigate = useNavigate();
  const [rows, setRows] = useState<TopologySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [armed, setArmed] = useState<string | null>(null);

  const arm = (key: string) => {
    setArmed(key);
    setTimeout(() => setArmed((prev) => (prev === key ? null : prev)), 4000);
  };

  const fetchRows = useCallback(async () => {
    try {
      const { data } = await api.get<ListResponse>('/topologies/');
      setRows(data.data ?? []);
      setErr(null);
    } catch (e) {
      setErr((e as Error)?.message ?? 'failed to list topologies');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => { if (!cancelled) await fetchRows(); };
    tick();
    const iv = setInterval(tick, 5000);
    return () => { cancelled = true; clearInterval(iv); };
  }, [fetchRows]);

  const onCreate = async () => {
    const name = newName.trim();
    if (!name) return;
    setBusy('create');
    try {
      const { data: created } = await api.post<TopologySummary>('/topologies/blank', { name });
      navigate(`/mazenet?topology=${created.id}`);
    } catch (e) {
      setErr((e as Error)?.message ?? 'create failed');
    } finally {
      setBusy(null);
      setCreating(false);
      setNewName('');
    }
  };

  const onDelete = async (id: string) => {
    setBusy(id);
    try {
      await api.delete(`/topologies/${id}`);
      await fetchRows();
    } catch (e) {
      setErr((e as Error)?.message ?? 'delete failed');
    } finally {
      setBusy(null);
      setArmed(null);
    }
  };

  const onDeploy = async (id: string) => {
    setBusy(id);
    try {
      await api.post(`/topologies/${id}/deploy`, {});
      await fetchRows();
    } catch (e) {
      setErr((e as Error)?.message ?? 'deploy failed');
    } finally {
      setBusy(null);
    }
  };

  const onTeardown = async (id: string) => {
    setBusy(id);
    try {
      await api.post(`/topologies/${id}/teardown`, {});
      await fetchRows();
    } catch (e) {
      setErr((e as Error)?.message ?? 'teardown failed');
    } finally {
      setBusy(null);
      setArmed(null);
    }
  };

  return (
    <div className="tlist-page">
      <div className="tlist-header">
        <div>
          <h1>TOPOLOGIES</h1>
          <div className="tlist-sub">
            {loading ? 'loading…' : `${rows.length} topology${rows.length === 1 ? '' : 'ies'}`}
            {err && <span className="alert-text"> · {err}</span>}
          </div>
        </div>
        <div className="tlist-actions">
          <button type="button" className="tlist-btn ghost" onClick={fetchRows} title="Refresh">
            <RefreshCw size={12} /> REFRESH
          </button>
          <button type="button" className="tlist-btn" onClick={() => setCreating((v) => !v)}>
            <Plus size={12} /> NEW TOPOLOGY
          </button>
        </div>
      </div>

      {creating && (
        <div className="tlist-create-row">
          <input
            type="text"
            autoFocus
            placeholder="topology name (e.g. honeynet-dev)"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') onCreate();
              if (e.key === 'Escape') { setCreating(false); setNewName(''); }
            }}
          />
          <button type="button" className="tlist-btn" disabled={!newName.trim() || busy === 'create'} onClick={onCreate}>
            CREATE
          </button>
          <button type="button" className="tlist-btn ghost" onClick={() => { setCreating(false); setNewName(''); }}>
            CANCEL
          </button>
        </div>
      )}

      <div className="tlist-grid">
        {rows.map((r) => (
          <div key={r.id} className="tlist-card" onClick={() => navigate(`/mazenet?topology=${r.id}`)}>
            <div className="tlist-card-top">
              <Network size={14} className="violet-accent" />
              <div className="tlist-card-name">{r.name}</div>
              <span className={`tlist-pill ${statusClass(r.status)}`}>{r.status}</span>
            </div>
            <div className="tlist-card-meta">
              <span>mode: {r.mode}</span>
              <span>v{r.version}</span>
              <span>{new Date(r.created_at).toLocaleString()}</span>
            </div>
            <div className="tlist-card-id">{r.id}</div>
            <div className="tlist-card-actions" onClick={(e) => e.stopPropagation()}>
              {r.status === 'pending' && (
                <button
                  type="button"
                  className="tlist-btn small"
                  disabled={busy === r.id}
                  onClick={() => onDeploy(r.id)}
                  title="Deploy this topology"
                >
                  <UploadCloud size={10} /> DEPLOY
                </button>
              )}
              {['active', 'degraded', 'failed', 'deploying'].includes(r.status) && (
                <button
                  type="button"
                  className={`tlist-btn small warn ${armed === `td:${r.id}` ? 'armed' : ''}`}
                  disabled={busy === r.id}
                  onClick={() => armed === `td:${r.id}` ? onTeardown(r.id) : arm(`td:${r.id}`)}
                  title={armed === `td:${r.id}` ? 'Click again to confirm teardown' : 'Teardown this topology'}
                >
                  <Power size={10} /> {armed === `td:${r.id}` ? 'CONFIRM?' : 'TEARDOWN'}
                </button>
              )}
              <button
                type="button"
                className={`tlist-btn small danger ${armed === r.id ? 'armed' : ''}`}
                disabled={busy === r.id}
                onClick={() => armed === r.id ? onDelete(r.id) : arm(r.id)}
                title={armed === r.id ? 'Click again to confirm' : 'Delete'}
              >
                <Trash2 size={10} /> {armed === r.id ? 'CONFIRM?' : 'DELETE'}
              </button>
            </div>
          </div>
        ))}
        {!loading && rows.length === 0 && (
          <div className="tlist-empty">
            No topologies yet. Click NEW TOPOLOGY to create one.
          </div>
        )}
      </div>
    </div>
  );
};

export default TopologyList;
