import React, { useEffect, useState } from 'react';
import api from '../utils/api';
import { Settings, Users, Sliders, Trash2, UserPlus, Key, Save, Shield, AlertTriangle, Palette, Activity, Square, RefreshCw, Play } from '../icons';
import { useToast } from './Toasts/useToast';
import './Dashboard.css';
import './Config.css';

interface UserEntry {
  uuid: string;
  username: string;
  role: string;
  must_change_password: boolean;
}

interface ConfigData {
  role: string;
  deployment_limit: number;
  global_mutation_interval: string;
  users?: UserEntry[];
  developer_mode?: boolean;
}

const Config: React.FC = () => {
  const [config, setConfig] = useState<ConfigData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'limits' | 'users' | 'globals' | 'appearance' | 'workers'>('limits');
  const [accent, setAccent] = useState<'matrix' | 'violet'>(() => {
    try {
      const raw = localStorage.getItem('decnet_tweaks');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed?.accent === 'violet') return 'violet';
      }
    } catch { /* noop */ }
    return 'matrix';
  });
  const { push: pushToast } = useToast();

  const handleAccentChange = (value: 'matrix' | 'violet') => {
    setAccent(value);
    let existing: Record<string, unknown> = {};
    try {
      const raw = localStorage.getItem('decnet_tweaks');
      if (raw) existing = JSON.parse(raw) ?? {};
    } catch { existing = {}; }
    localStorage.setItem('decnet_tweaks', JSON.stringify({ ...existing, accent: value }));
    document.documentElement.setAttribute('data-accent', value);
    pushToast({ text: `ACCENT · ${value.toUpperCase()}`, icon: 'check-circle', tone: 'violet' });
  };

  // Deployment limit state
  const [limitInput, setLimitInput] = useState('');
  const [limitSaving, setLimitSaving] = useState(false);
  const [limitMsg, setLimitMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Global mutation interval state
  const [intervalInput, setIntervalInput] = useState('');
  const [intervalSaving, setIntervalSaving] = useState(false);
  const [intervalMsg, setIntervalMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Add user form state
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<'admin' | 'viewer'>('viewer');
  const [addingUser, setAddingUser] = useState(false);
  const [userMsg, setUserMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Confirm delete state
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  // Reset password state
  const [resetTarget, setResetTarget] = useState<string | null>(null);
  const [resetPassword, setResetPassword] = useState('');

  // Reinit state
  const [confirmReinit, setConfirmReinit] = useState(false);
  const [reiniting, setReiniting] = useState(false);
  const [reinitMsg, setReinitMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const isAdmin = config?.role === 'admin';

  const fetchConfig = async () => {
    try {
      const res = await api.get('/config');
      setConfig(res.data);
      setLimitInput(String(res.data.deployment_limit));
      setIntervalInput(res.data.global_mutation_interval);
    } catch (err) {
      console.error('Failed to fetch config', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  // If server didn't send users, force tab away from users
  useEffect(() => {
    if (config && !config.users && activeTab === 'users') {
      setActiveTab('limits');
    }
  }, [config, activeTab]);

  const handleSaveLimit = async () => {
    const val = parseInt(limitInput);
    if (isNaN(val) || val < 1 || val > 500) {
      setLimitMsg({ type: 'error', text: 'VALUE MUST BE 1-500' });
      return;
    }
    setLimitSaving(true);
    setLimitMsg(null);
    try {
      await api.put('/config/deployment-limit', { deployment_limit: val });
      setLimitMsg({ type: 'success', text: 'DEPLOYMENT LIMIT UPDATED' });
      fetchConfig();
    } catch (err: any) {
      setLimitMsg({ type: 'error', text: err.response?.data?.detail || 'UPDATE FAILED' });
    } finally {
      setLimitSaving(false);
    }
  };

  const handleSaveInterval = async () => {
    if (!/^[1-9]\d*[mdMyY]$/.test(intervalInput)) {
      setIntervalMsg({ type: 'error', text: 'INVALID FORMAT (e.g. 30m, 1d, 6M)' });
      return;
    }
    setIntervalSaving(true);
    setIntervalMsg(null);
    try {
      await api.put('/config/global-mutation-interval', { global_mutation_interval: intervalInput });
      setIntervalMsg({ type: 'success', text: 'MUTATION INTERVAL UPDATED' });
      fetchConfig();
    } catch (err: any) {
      setIntervalMsg({ type: 'error', text: err.response?.data?.detail || 'UPDATE FAILED' });
    } finally {
      setIntervalSaving(false);
    }
  };

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword.trim()) return;
    setAddingUser(true);
    setUserMsg(null);
    try {
      await api.post('/config/users', {
        username: newUsername.trim(),
        password: newPassword,
        role: newRole,
      });
      setNewUsername('');
      setNewPassword('');
      setNewRole('viewer');
      setUserMsg({ type: 'success', text: 'USER CREATED' });
      fetchConfig();
    } catch (err: any) {
      setUserMsg({ type: 'error', text: err.response?.data?.detail || 'CREATE FAILED' });
    } finally {
      setAddingUser(false);
    }
  };

  const handleDeleteUser = async (uuid: string) => {
    try {
      await api.delete(`/config/users/${uuid}`);
      setConfirmDelete(null);
      fetchConfig();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Delete failed');
    }
  };

  const handleRoleChange = async (uuid: string, role: string) => {
    try {
      await api.put(`/config/users/${uuid}/role`, { role });
      fetchConfig();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Role update failed');
    }
  };

  const handleResetPassword = async (uuid: string) => {
    if (!resetPassword.trim() || resetPassword.length < 8) {
      alert('Password must be at least 8 characters');
      return;
    }
    try {
      await api.put(`/config/users/${uuid}/reset-password`, { new_password: resetPassword });
      setResetTarget(null);
      setResetPassword('');
      fetchConfig();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Password reset failed');
    }
  };

  const handleReinit = async () => {
    setReiniting(true);
    setReinitMsg(null);
    try {
      const res = await api.delete('/config/reinit');
      const d = res.data.deleted;
      setReinitMsg({ type: 'success', text: `PURGED: ${d.logs} logs, ${d.bounties} bounties, ${d.attackers} attacker profiles` });
      setConfirmReinit(false);
    } catch (err: any) {
      setReinitMsg({ type: 'error', text: err.response?.data?.detail || 'REINIT FAILED' });
    } finally {
      setReiniting(false);
    }
  };

  if (loading) {
    return (
      <div className="logs-section">
        <div className="loader">LOADING CONFIGURATION...</div>
      </div>
    );
  }

  if (!config) {
    return (
      <div className="logs-section">
        <div style={{ padding: '40px', textAlign: 'center', opacity: 0.5 }}>
          <p>FAILED TO LOAD CONFIGURATION</p>
        </div>
      </div>
    );
  }

  const tabs: { key: string; label: string; icon: React.ReactNode }[] = [
    { key: 'limits', label: 'DEPLOYMENT LIMITS', icon: <Sliders size={14} /> },
    ...(config.users
      ? [{ key: 'users', label: 'USER MANAGEMENT', icon: <Users size={14} /> }]
      : []),
    { key: 'globals', label: 'GLOBAL VALUES', icon: <Settings size={14} /> },
    { key: 'appearance', label: 'APPEARANCE', icon: <Palette size={14} /> },
    ...(isAdmin ? [{ key: 'workers', label: 'WORKERS', icon: <Activity size={14} /> }] : []),
  ];

  return (
    <div className="config-page">
      <div className="logs-section">
        <div className="section-header">
          <Shield size={20} />
          <h2>SYSTEM CONFIGURATION</h2>
        </div>
      </div>

      <div className="config-tabs">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            className={`config-tab ${activeTab === tab.key ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.key as any)}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* DEPLOYMENT LIMITS TAB */}
      {activeTab === 'limits' && (
        <div className="config-panel">
          <div className="config-field">
            <span className="config-label">MAXIMUM DECKIES PER DEPLOYMENT</span>
            {isAdmin ? (
              <>
                <div className="config-input-row">
                  <input
                    type="number"
                    min={1}
                    max={500}
                    value={limitInput}
                    onChange={(e) => setLimitInput(e.target.value)}
                  />
                  <div className="preset-buttons">
                    {[10, 50, 100, 200].map((v) => (
                      <button
                        key={v}
                        className={`preset-btn ${limitInput === String(v) ? 'active' : ''}`}
                        onClick={() => setLimitInput(String(v))}
                      >
                        {v}
                      </button>
                    ))}
                  </div>
                  <button
                    className="save-btn"
                    onClick={handleSaveLimit}
                    disabled={limitSaving}
                  >
                    <Save size={14} />
                    {limitSaving ? 'SAVING...' : 'SAVE'}
                  </button>
                </div>
                {limitMsg && (
                  <span className={limitMsg.type === 'success' ? 'config-success' : 'config-error'}>
                    {limitMsg.text}
                  </span>
                )}
              </>
            ) : (
              <span className="config-value">{config.deployment_limit}</span>
            )}
          </div>
        </div>
      )}

      {/* USER MANAGEMENT TAB (only if server sent users) */}
      {activeTab === 'users' && config.users && (
        <div className="config-panel">
          <div className="users-table-container">
            <table className="users-table">
              <thead>
                <tr>
                  <th>USERNAME</th>
                  <th>ROLE</th>
                  <th>STATUS</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {config.users.map((user) => (
                  <tr key={user.uuid}>
                    <td>{user.username}</td>
                    <td>
                      <span className={`role-badge ${user.role}`}>{user.role.toUpperCase()}</span>
                    </td>
                    <td>
                      {user.must_change_password && (
                        <span className="must-change-badge">MUST CHANGE PASSWORD</span>
                      )}
                    </td>
                    <td>
                      <div className="user-actions">
                        {/* Role change dropdown */}
                        <select
                          className="role-select"
                          value={user.role}
                          onChange={(e) => handleRoleChange(user.uuid, e.target.value)}
                        >
                          <option value="admin">admin</option>
                          <option value="viewer">viewer</option>
                        </select>

                        {/* Reset password */}
                        {resetTarget === user.uuid ? (
                          <div className="confirm-dialog">
                            <input
                              type="password"
                              placeholder="New password"
                              value={resetPassword}
                              onChange={(e) => setResetPassword(e.target.value)}
                              style={{ width: '140px' }}
                            />
                            <button className="action-btn" onClick={() => handleResetPassword(user.uuid)}>
                              SET
                            </button>
                            <button className="action-btn" onClick={() => { setResetTarget(null); setResetPassword(''); }}>
                              CANCEL
                            </button>
                          </div>
                        ) : (
                          <button
                            className="action-btn"
                            onClick={() => setResetTarget(user.uuid)}
                          >
                            <Key size={12} />
                            RESET
                          </button>
                        )}

                        {/* Delete */}
                        {confirmDelete === user.uuid ? (
                          <div className="confirm-dialog">
                            <span>CONFIRM?</span>
                            <button className="action-btn danger" onClick={() => handleDeleteUser(user.uuid)}>
                              YES
                            </button>
                            <button className="action-btn" onClick={() => setConfirmDelete(null)}>
                              NO
                            </button>
                          </div>
                        ) : (
                          <button
                            className="action-btn danger"
                            onClick={() => setConfirmDelete(user.uuid)}
                          >
                            <Trash2 size={12} />
                            DELETE
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="add-user-section">
            <form className="add-user-form" onSubmit={handleAddUser}>
              <div className="form-group">
                <label>USERNAME</label>
                <input
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  required
                  minLength={1}
                  maxLength={64}
                />
              </div>
              <div className="form-group">
                <label>PASSWORD</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  minLength={8}
                  maxLength={72}
                />
              </div>
              <div className="form-group">
                <label>ROLE</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as 'admin' | 'viewer')}
                >
                  <option value="viewer">viewer</option>
                  <option value="admin">admin</option>
                </select>
              </div>
              <button type="submit" className="save-btn" disabled={addingUser}>
                <UserPlus size={14} />
                {addingUser ? 'CREATING...' : 'ADD USER'}
              </button>
              {userMsg && (
                <span className={userMsg.type === 'success' ? 'config-success' : 'config-error'}>
                  {userMsg.text}
                </span>
              )}
            </form>
          </div>
        </div>
      )}

      {/* GLOBAL VALUES TAB */}
      {activeTab === 'globals' && (
        <div className="config-panel">
          <div className="config-field">
            <span className="config-label">GLOBAL MUTATION INTERVAL</span>
            {isAdmin ? (
              <>
                <div className="config-input-row">
                  <input
                    type="text"
                    value={intervalInput}
                    onChange={(e) => setIntervalInput(e.target.value)}
                    placeholder="30m"
                  />
                  <button
                    className="save-btn"
                    onClick={handleSaveInterval}
                    disabled={intervalSaving}
                  >
                    <Save size={14} />
                    {intervalSaving ? 'SAVING...' : 'SAVE'}
                  </button>
                </div>
                <span className="interval-hint">
                  FORMAT: &lt;number&gt;&lt;unit&gt; — m=minutes, d=days, M=months, y=years (e.g. 30m, 7d, 1M)
                </span>
                {intervalMsg && (
                  <span className={intervalMsg.type === 'success' ? 'config-success' : 'config-error'}>
                    {intervalMsg.text}
                  </span>
                )}
              </>
            ) : (
              <span className="config-value">{config.global_mutation_interval}</span>
            )}
          </div>
        </div>
      )}

      {/* WORKERS TAB (admin only, server-gated too) */}
      {activeTab === 'workers' && isAdmin && (
        <WorkersPanel pushToast={pushToast} />
      )}

      {/* APPEARANCE TAB */}
      {activeTab === 'appearance' && (
        <div className="config-panel">
          <div className="config-field">
            <span className="config-label">ACCENT COLOR</span>
            <p style={{ fontSize: '0.75rem', opacity: 0.5, margin: '4px 0 12px' }}>
              Swaps the UI accent (nav bars, hover glows, chip borders) between matrix-green and electric-violet. Persists per-browser.
            </p>
            <div style={{ display: 'flex', gap: '8px' }}>
              {(['matrix', 'violet'] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => handleAccentChange(value)}
                  className="save-btn"
                  style={{
                    padding: '8px 16px',
                    fontSize: '0.75rem',
                    letterSpacing: '1.5px',
                    borderColor: accent === value
                      ? (value === 'violet' ? 'var(--violet)' : 'var(--matrix)')
                      : 'var(--border)',
                    color: accent === value
                      ? (value === 'violet' ? 'var(--violet)' : 'var(--matrix)')
                      : 'var(--matrix)',
                    opacity: accent === value ? 1 : 0.6,
                    background: 'transparent',
                  }}
                >
                  {accent === value ? '● ' : '○ '}
                  {value.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* DANGER ZONE — developer mode only, server-gated, shown on globals tab */}
      {activeTab === 'globals' && config.developer_mode && (
        <div className="config-panel" style={{ borderColor: '#ff4141' }}>
          <div className="config-field" style={{ marginBottom: 0 }}>
            <span className="config-label" style={{ color: '#ff4141' }}>
              <AlertTriangle size={12} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '6px' }} />
              DANGER ZONE — DEVELOPER MODE
            </span>
            <p style={{ fontSize: '0.75rem', opacity: 0.5, margin: '4px 0 12px' }}>
              Purge all logs, bounty vault entries, and attacker profiles. This action is irreversible.
            </p>
            {!confirmReinit ? (
              <button
                className="action-btn danger"
                onClick={() => setConfirmReinit(true)}
                style={{ padding: '8px 16px', fontSize: '0.8rem' }}
              >
                <Trash2 size={14} />
                PURGE ALL DATA
              </button>
            ) : (
              <div className="confirm-dialog">
                <span>THIS WILL DELETE ALL COLLECTED DATA. ARE YOU SURE?</span>
                <button
                  className="action-btn danger"
                  onClick={handleReinit}
                  disabled={reiniting}
                  style={{ padding: '6px 16px' }}
                >
                  {reiniting ? 'PURGING...' : 'YES, PURGE'}
                </button>
                <button
                  className="action-btn"
                  onClick={() => setConfirmReinit(false)}
                  style={{ padding: '6px 16px' }}
                >
                  CANCEL
                </button>
              </div>
            )}
            {reinitMsg && (
              <span className={reinitMsg.type === 'success' ? 'config-success' : 'config-error'} style={{ marginTop: '8px' }}>
                {reinitMsg.text}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

// ─── Workers panel ────────────────────────────────────────────────────────────
// Pollster view backed by GET /workers.  Every 5s we pull the full snapshot;
// the registry is cheap (in-memory dict) so there's no need for SSE here.

interface WorkerStatusRow {
  name: string;
  status: 'ok' | 'stale' | 'unknown';
  last_heartbeat_ts: number | null;
  seconds_since: number | null;
  extra: Record<string, unknown>;
  installed: boolean;
}

interface WorkersPanelProps {
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
    : breaker === 'half_open' ? '#ffaa00'
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

const WorkersPanel: React.FC<WorkersPanelProps> = ({ pushToast }) => {
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
            background: 'rgba(255, 170, 0, 0.08)',
            color: '#ffaa00',
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
                       : w.status === 'stale' ? '#ffaa00'
                       : 'rgba(255,255,255,0.4)',
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
                      color: canStop ? '#ff4d4d' : '#ff4d4d',
                      borderColor: canStop ? '#ff4d4d' : 'rgba(255, 77, 77, 0.4)',
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

export default Config;
