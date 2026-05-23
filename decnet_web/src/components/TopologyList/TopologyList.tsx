// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Network, Plus, Power, Trash2, UploadCloud, RefreshCw, Skull, Server, Cpu, Mail } from '../../icons';
import api from '../../utils/api';
import { useSwarmHosts } from '../../hooks/useSwarmHosts';
import { clearLayout } from '../MazeNET/useMazeLayoutStore';
import CreateTopologyWizard from './CreateTopologyWizard';
import EmptyState from '../EmptyState/EmptyState';
import './TopologyList.css';

interface TopologySummary {
  id: string;
  name: string;
  mode: string;
  target_host_uuid: string | null;
  status: string;
  version: number;
  needs_resync?: boolean;
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
  const { byUuid: hostsByUuid } = useSwarmHosts();
  const [rows, setRows] = useState<TopologySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [armed, setArmed] = useState<string | null>(null);
  const [reaping, setReaping] = useState(false);
  const [reapMsg, setReapMsg] = useState<string | null>(null);

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

  const onCreated = (row: TopologySummary) => {
    setCreating(false);
    navigate(`/mazenet?topology=${row.id}`);
  };

  const onDelete = async (id: string) => {
    setBusy(id);
    try {
      await api.delete(`/topologies/${id}`);
      clearLayout(id);
      await fetchRows();
    } catch (e) {
      setErr((e as Error)?.message ?? 'delete failed');
    } finally {
      setBusy(null);
      setArmed(null);
    }
  };

  const onReapOrphans = async () => {
    setReaping(true);
    setReapMsg(null);
    try {
      const { data } = await api.post<{
        orphan_prefixes: string[];
        containers_removed: string[];
        networks_removed: string[];
        errors: string[];
      }>('/topologies/reap-orphans', {});
      const c = data.containers_removed.length;
      const n = data.networks_removed.length;
      const e = data.errors.length;
      if (c === 0 && n === 0 && e === 0) {
        setReapMsg('no orphans found');
      } else {
        setReapMsg(`removed ${c} container(s), ${n} network(s)${e ? `, ${e} error(s)` : ''}`);
      }
      await fetchRows();
    } catch (e) {
      setReapMsg((e as Error)?.message ?? 'reap failed');
    } finally {
      setReaping(false);
      setArmed(null);
      setTimeout(() => setReapMsg(null), 6000);
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
    <div className="tlist-root tlist-page">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Network size={22} className="violet-accent" />
            <h1>TOPOLOGIES</h1>
          </div>
          <span className="page-sub">
            {loading ? 'LOADING…' : `${rows.length} ${rows.length === 1 ? 'TOPOLOGY' : 'TOPOLOGIES'}`}
            {err && <span className="alert-text"> · {err}</span>}
            {reapMsg && <span className="alert-text"> · reap: {reapMsg}</span>}
          </span>
        </div>
        <div className="tlist-actions">
          <button type="button" className="tlist-btn ghost" onClick={fetchRows} title="Refresh">
            <RefreshCw size={12} /> REFRESH
          </button>
          <button
            type="button"
            className={`tlist-btn ghost warn ${armed === 'reap' ? 'armed' : ''}`}
            disabled={reaping}
            onClick={() => armed === 'reap' ? onReapOrphans() : arm('reap')}
            title={armed === 'reap'
              ? 'Click again to force-remove Docker resources for deleted topologies'
              : 'Reap orphan Docker resources (admin)'}
          >
            <Skull size={12} /> {reaping ? 'REAPING…' : armed === 'reap' ? 'CONFIRM?' : 'REAP ORPHANS'}
          </button>
          <button type="button" className="tlist-btn" onClick={() => setCreating(true)}>
            <Plus size={12} /> NEW TOPOLOGY
          </button>
        </div>
      </div>

      <CreateTopologyWizard
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={onCreated}
      />

      {!loading && rows.length === 0 ? (
        <div className="tlist-empty-wrap">
          <EmptyState
            icon={Network}
            title="NO TOPOLOGIES YET"
            hint="spin one up to deploy a honeynet"
            cta={{ label: 'NEW TOPOLOGY', icon: Plus, onClick: () => setCreating(true) }}
          />
        </div>
      ) : (
      <div className="tlist-grid">
        {rows.map((r) => (
          <div key={r.id} className="tlist-card" onClick={() => navigate(`/mazenet?topology=${r.id}`)}>
            <div className="tlist-card-top">
              <Network size={14} className="violet-accent" />
              <div className="tlist-card-name">{r.name}</div>
              <span className={`tlist-pill ${statusClass(r.status)}`}>{r.status}</span>
            </div>
            <div className="tlist-card-meta">
              {r.mode === 'agent' && r.target_host_uuid ? (
                <span title={r.target_host_uuid}>
                  <Server size={11} style={{ marginRight: 4, verticalAlign: '-1px' }} />
                  {hostsByUuid.get(r.target_host_uuid)?.name ?? `host:${r.target_host_uuid.slice(0, 8)}`}
                </span>
              ) : (
                <span>
                  <Cpu size={11} style={{ marginRight: 4, verticalAlign: '-1px' }} />
                  master
                </span>
              )}
              <span>v{r.version}</span>
              <span>{new Date(r.created_at).toLocaleString()}</span>
            </div>
            <div className="tlist-card-id">{r.id}</div>
            <div className="tlist-card-actions" onClick={(e) => e.stopPropagation()}>
              <button
                type="button"
                className="tlist-btn small"
                onClick={() => navigate(`/topologies/${r.id}/personas`)}
                title="Edit email personas for this topology"
              >
                <Mail size={10} /> PERSONAS
              </button>
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
              {!['active', 'degraded', 'deploying'].includes(r.status) && (
                <button
                  type="button"
                  className={`tlist-btn small danger ${armed === r.id ? 'armed' : ''}`}
                  disabled={busy === r.id}
                  onClick={() => armed === r.id ? onDelete(r.id) : arm(r.id)}
                  title={armed === r.id ? 'Click again to confirm' : 'Delete'}
                >
                  <Trash2 size={10} /> {armed === r.id ? 'CONFIRM?' : 'DELETE'}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
      )}
    </div>
  );
};

export default TopologyList;
