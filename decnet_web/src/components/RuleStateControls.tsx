// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useState } from 'react';
import { Crosshair, Shield, ShieldOff } from '../icons';
import api from '../utils/api';
import EmptyState from './EmptyState/EmptyState';

/*
 * RuleStateControls — admin-only rule operational state panel.
 *
 * Server-gated via require_admin on the API; this component is also
 * conditionally rendered on the role flag from /config so a non-admin
 * never sees the controls. Per feedback_serverside_ui.md the
 * client-side gate is a UX nicety, NOT a security boundary — the
 * server returns 403 either way.
 */

interface RuleRow {
  rule_id: string;
  rule_version: number;
  name: string;
  description: string;
  state: 'enabled' | 'disabled' | 'clipped';
  confidence_max: number | null;
  expires_at: string | null;
  reason: string | null;
  set_by: string | null;
  set_at: string | null;
}

const RuleStateControls: React.FC = () => {
  const [rules, setRules] = useState<RuleRow[]>([]);
  const [isAdmin, setIsAdmin] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const res = await api.get('/ttp/rules');
      setRules(Array.isArray(res.data) ? res.data : []);
    } catch {
      setRules([]);
    } finally {
      setLoaded(true);
    }
  };

  useEffect(() => {
    const probe = async () => {
      try {
        const cfg = await api.get('/config');
        setIsAdmin(cfg.data?.role === 'admin');
      } catch {
        setIsAdmin(false);
      }
      refresh();
    };
    probe();
  }, []);

  const setState = async (
    ruleId: string,
    state: 'enabled' | 'disabled' | 'clipped',
    confidence_max?: number,
  ) => {
    setBusy(ruleId);
    try {
      await api.post(`/ttp/rules/${ruleId}/state`, {
        state,
        confidence_max: confidence_max ?? null,
        expires_at: null,
        reason: null,
      });
      await refresh();
    } catch {
      // best-effort; failures show on next refresh
    } finally {
      setBusy(null);
    }
  };

  const revert = async (ruleId: string) => {
    setBusy(ruleId);
    try {
      await api.delete(`/ttp/rules/${ruleId}/state`);
      await refresh();
    } catch {
      // ignored
    } finally {
      setBusy(null);
    }
  };

  if (!isAdmin) {
    return null;
  }

  return (
    <div className="logs-section">
      <div className="section-header">
        <div className="section-title">
          <Shield size={14} />
          <span>RULE STATE — ADMIN</span>
        </div>
      </div>
      <div className="logs-table-container">
        {!loaded ? null : rules.length === 0 ? (
          <EmptyState icon={Crosshair} title="NO RULES LOADED" />
        ) : (
          <table className="logs-table">
            <thead>
              <tr>
                <th>RULE</th>
                <th>NAME</th>
                <th>STATE</th>
                <th>CLIP</th>
                <th style={{ textAlign: 'right' }}>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.rule_id}>
                  <td className="matrix-text">{r.rule_id}</td>
                  <td>{r.name}</td>
                  <td>
                    <span className={`chip ${r.state === 'enabled' ? 'violet' : 'dim-chip'}`}>
                      {r.state.toUpperCase()}
                    </span>
                  </td>
                  <td className="dim">
                    {r.confidence_max !== null ? r.confidence_max.toFixed(2) : '—'}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      type="button"
                      className="btn"
                      disabled={busy === r.rule_id || r.state === 'disabled'}
                      onClick={() => setState(r.rule_id, 'disabled')}
                      title="Disable this rule"
                    >
                      <ShieldOff size={12} />
                    </button>
                    <button
                      type="button"
                      className="btn"
                      style={{ marginLeft: 6 }}
                      disabled={busy === r.rule_id}
                      onClick={() => setState(r.rule_id, 'clipped', 0.5)}
                      title="Clip confidence to 0.5"
                    >
                      CLIP
                    </button>
                    <button
                      type="button"
                      className="btn"
                      style={{ marginLeft: 6 }}
                      disabled={busy === r.rule_id || r.state === 'enabled'}
                      onClick={() => revert(r.rule_id)}
                      title="Revert to default enabled state"
                    >
                      REVERT
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default RuleStateControls;
