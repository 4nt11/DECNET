import React, { useState } from 'react';
import { Save } from '../../../icons';
import type { FormMsg } from '../types';

interface Props {
  isAdmin: boolean;
  initialValue: number;
  onSave: (n: number) => Promise<{ ok: true } | { ok: false; reason: string }>;
}

const PRESETS = [10, 50, 100, 200] as const;

/** DEPLOYMENT LIMITS tab — admins edit + save; viewers see the
 *  current value as static text. The inline FormMsg chip renders
 *  the success/error result from the hook mutation. */
export const LimitsTab: React.FC<Props> = ({ isAdmin, initialValue, onSave }) => {
  const [input, setInput] = useState(String(initialValue));
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<FormMsg | null>(null);

  const handleSave = async () => {
    const val = parseInt(input);
    if (isNaN(val) || val < 1 || val > 500) {
      setMsg({ type: 'error', text: 'VALUE MUST BE 1-500' });
      return;
    }
    setSaving(true);
    setMsg(null);
    const r = await onSave(val);
    setMsg(r.ok
      ? { type: 'success', text: 'DEPLOYMENT LIMIT UPDATED' }
      : { type: 'error', text: r.reason });
    setSaving(false);
  };

  return (
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
                value={input}
                onChange={(e) => setInput(e.target.value)}
              />
              <div className="preset-buttons">
                {PRESETS.map((v) => (
                  <button
                    key={v}
                    className={`preset-btn ${input === String(v) ? 'active' : ''}`}
                    onClick={() => setInput(String(v))}
                  >
                    {v}
                  </button>
                ))}
              </div>
              <button className="save-btn" onClick={handleSave} disabled={saving}>
                <Save size={14} />
                {saving ? 'SAVING...' : 'SAVE'}
              </button>
            </div>
            {msg && (
              <span className={msg.type === 'success' ? 'config-success' : 'config-error'}>
                {msg.text}
              </span>
            )}
          </>
        ) : (
          <span className="config-value">{initialValue}</span>
        )}
      </div>
    </div>
  );
};
