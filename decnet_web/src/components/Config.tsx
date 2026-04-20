import React, { useEffect, useState } from 'react';
import api from '../utils/api';
import { Settings, Users, Sliders, Trash2, UserPlus, Key, Save, Shield, AlertTriangle } from 'lucide-react';
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
  const [activeTab, setActiveTab] = useState<'limits' | 'users' | 'globals'>('limits');

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

export default Config;
