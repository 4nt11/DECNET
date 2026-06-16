// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from 'react';
import { AlertTriangle, Save, Trash2 } from '../../../icons';
import type { FormMsg } from '../types';

type MutationResult = { ok: true } | { ok: false; reason: string };
type ReinitTotals = { logs: number; bounties: number; attackers: number };
type ReinitResult =
  | { ok: true; deleted: ReinitTotals }
  | { ok: false; reason: string };

interface Props {
  isAdmin: boolean;
  developerMode: boolean;
  initialInterval: string;
  onSaveInterval: (s: string) => Promise<MutationResult>;
  onReinit: () => Promise<ReinitResult>;
}

const INTERVAL_RE = /^[1-9]\d*[mdMyY]$/;

/** GLOBAL VALUES tab — global mutation interval form, plus the
 *  developer-mode-gated DANGER ZONE that purges all collected data. */
export const GlobalsTab: React.FC<Props> = ({
  isAdmin, developerMode, initialInterval,
  onSaveInterval, onReinit,
}) => {
  const [intervalInput, setIntervalInput] = useState(initialInterval);
  const [intervalSaving, setIntervalSaving] = useState(false);
  const [intervalMsg, setIntervalMsg] = useState<FormMsg | null>(null);

  const [confirmReinit, setConfirmReinit] = useState(false);
  const [reiniting, setReiniting] = useState(false);
  const [reinitMsg, setReinitMsg] = useState<FormMsg | null>(null);

  const handleSaveInterval = async () => {
    if (!INTERVAL_RE.test(intervalInput)) {
      setIntervalMsg({ type: 'error', text: 'INVALID FORMAT (e.g. 30m, 1d, 6M)' });
      return;
    }
    setIntervalSaving(true);
    setIntervalMsg(null);
    const r = await onSaveInterval(intervalInput);
    setIntervalMsg(r.ok
      ? { type: 'success', text: 'MUTATION INTERVAL UPDATED' }
      : { type: 'error', text: r.reason });
    setIntervalSaving(false);
  };

  const handleReinit = async () => {
    setReiniting(true);
    setReinitMsg(null);
    const r = await onReinit();
    if (r.ok) {
      const d = r.deleted;
      setReinitMsg({
        type: 'success',
        text: `PURGED: ${d.logs} logs, ${d.bounties} bounties, ${d.attackers} attacker profiles`,
      });
      setConfirmReinit(false);
    } else {
      setReinitMsg({ type: 'error', text: r.reason });
    }
    setReiniting(false);
  };

  return (
    <>
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
            <span className="config-value">{initialInterval}</span>
          )}
        </div>
      </div>

      {developerMode && (
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
    </>
  );
};
