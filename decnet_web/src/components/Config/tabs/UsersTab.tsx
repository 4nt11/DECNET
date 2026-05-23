// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from 'react';
import { Key, Trash2, UserPlus } from '../../../icons';
import type { FormMsg, UserEntry } from '../types';

type MutationResult = { ok: true } | { ok: false; reason: string };

interface Props {
  users: UserEntry[];
  onDeleteUser: (uuid: string) => Promise<MutationResult>;
  onSetUserRole: (uuid: string, role: string) => Promise<MutationResult>;
  onResetUserPassword: (uuid: string, newPassword: string) => Promise<MutationResult>;
  onAddUser: (input: {
    username: string;
    password: string;
    role: 'admin' | 'viewer';
  }) => Promise<MutationResult>;
}

/** USER MANAGEMENT tab — table of operators with per-row inline
 *  controls (role select, reset-password popup, two-step delete
 *  confirm) plus the "add user" form below the table. Surfaces
 *  errors via window.alert for the per-row mutations (matches the
 *  current behavior) and an inline FormMsg chip for the add form. */
export const UsersTab: React.FC<Props> = ({
  users,
  onDeleteUser,
  onSetUserRole,
  onResetUserPassword,
  onAddUser,
}) => {
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [resetTarget, setResetTarget] = useState<string | null>(null);
  const [resetPassword, setResetPassword] = useState('');

  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<'admin' | 'viewer'>('viewer');
  const [adding, setAdding] = useState(false);
  const [msg, setMsg] = useState<FormMsg | null>(null);

  const handleDelete = async (uuid: string) => {
    const r = await onDeleteUser(uuid);
    if (r.ok) {
      setConfirmDelete(null);
    } else {
      alert(r.reason);
    }
  };

  const handleRoleChange = async (uuid: string, role: string) => {
    const r = await onSetUserRole(uuid, role);
    if (!r.ok) alert(r.reason);
  };

  const handleResetPassword = async (uuid: string) => {
    if (!resetPassword.trim() || resetPassword.length < 8) {
      alert('Password must be at least 8 characters');
      return;
    }
    const r = await onResetUserPassword(uuid, resetPassword);
    if (r.ok) {
      setResetTarget(null);
      setResetPassword('');
    } else {
      alert(r.reason);
    }
  };

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword.trim()) return;
    setAdding(true);
    setMsg(null);
    const r = await onAddUser({
      username: newUsername.trim(),
      password: newPassword,
      role: newRole,
    });
    if (r.ok) {
      setNewUsername('');
      setNewPassword('');
      setNewRole('viewer');
      setMsg({ type: 'success', text: 'USER CREATED' });
    } else {
      setMsg({ type: 'error', text: r.reason });
    }
    setAdding(false);
  };

  return (
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
            {users.map((user) => (
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
                    <select
                      className="role-select"
                      value={user.role}
                      onChange={(e) => handleRoleChange(user.uuid, e.target.value)}
                    >
                      <option value="admin">admin</option>
                      <option value="viewer">viewer</option>
                    </select>

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
                      <button className="action-btn" onClick={() => setResetTarget(user.uuid)}>
                        <Key size={12} />
                        RESET
                      </button>
                    )}

                    {confirmDelete === user.uuid ? (
                      <div className="confirm-dialog">
                        <span>CONFIRM?</span>
                        <button className="action-btn danger" onClick={() => handleDelete(user.uuid)}>
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
        <form className="add-user-form" onSubmit={handleAdd}>
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
          <button type="submit" className="save-btn" disabled={adding}>
            <UserPlus size={14} />
            {adding ? 'CREATING...' : 'ADD USER'}
          </button>
          {msg && (
            <span className={msg.type === 'success' ? 'config-success' : 'config-error'}>
              {msg.text}
            </span>
          )}
        </form>
      </div>
    </div>
  );
};
