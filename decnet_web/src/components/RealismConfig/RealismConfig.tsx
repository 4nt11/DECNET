import React, { useEffect, useState } from 'react';
import api from '../../utils/api';
import { useToast } from '../Toasts/useToast';
import { Sliders, Save, RotateCcw } from '../../icons';

// ─── Types ───────────────────────────────────────────────────────────────────

interface WeightEntry {
  content_class: string;
  weight: number;
}

interface ConfigPayload {
  user_class_weights: WeightEntry[];
  system_class_weights: WeightEntry[];
  canary_class_weights: WeightEntry[];
  canary_probability: number;
}

const DEFAULTS: ConfigPayload = {
  user_class_weights: [
    { content_class: 'note', weight: 30 },
    { content_class: 'todo', weight: 20 },
    { content_class: 'draft', weight: 15 },
    { content_class: 'script', weight: 10 },
  ],
  system_class_weights: [
    { content_class: 'log_cron', weight: 12 },
    { content_class: 'log_daemon', weight: 8 },
    { content_class: 'cache_tmp', weight: 5 },
  ],
  canary_class_weights: [
    { content_class: 'canary_aws_creds', weight: 1 },
    { content_class: 'canary_env_file', weight: 1 },
    { content_class: 'canary_git_config', weight: 1 },
    { content_class: 'canary_ssh_key', weight: 1 },
    { content_class: 'canary_honeydoc', weight: 1 },
    { content_class: 'canary_honeydoc_docx', weight: 1 },
    { content_class: 'canary_honeydoc_pdf', weight: 1 },
    { content_class: 'canary_mysql_dump', weight: 1 },
  ],
  canary_probability: 0.03,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function pct(weights: WeightEntry[], idx: number): string {
  const total = weights.reduce((s, w) => s + Math.max(0, w.weight), 0);
  if (total === 0) return '—';
  return `${((weights[idx].weight / total) * 100).toFixed(1)}%`;
}

// ─── Subcomponent ────────────────────────────────────────────────────────────

const WeightTable: React.FC<{
  title: string;
  weights: WeightEntry[];
  onChange: (next: WeightEntry[]) => void;
}> = ({ title, weights, onChange }) => {
  const total = weights.reduce((s, w) => s + Math.max(0, w.weight), 0);
  return (
    <div style={{ marginBottom: '20px' }}>
      <div style={{
        fontSize: '0.7rem', color: 'var(--dim-color)', letterSpacing: '0.1em',
        marginBottom: '8px',
      }}>
        {title} · TOTAL {total}
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
        <tbody>
          {weights.map((w, i) => (
            <tr key={w.content_class} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <td className="mono" style={{ padding: '6px 12px', width: '40%' }}>
                {w.content_class}
              </td>
              <td style={{ padding: '6px 12px', width: '30%' }}>
                <input
                  type="number"
                  min={0}
                  step={1}
                  value={w.weight}
                  onChange={(e) => {
                    const next = weights.slice();
                    const v = parseInt(e.target.value, 10);
                    next[i] = { ...next[i], weight: Number.isFinite(v) ? Math.max(0, v) : 0 };
                    onChange(next);
                  }}
                  style={{
                    width: '80px',
                    backgroundColor: 'rgba(255,255,255,0.03)',
                    color: 'var(--text-color)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    padding: '4px 8px', fontFamily: 'inherit',
                  }}
                />
              </td>
              <td style={{ padding: '6px 12px', color: 'var(--dim-color)', fontVariantNumeric: 'tabular-nums' }}>
                {pct(weights, i)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

// ─── Page ────────────────────────────────────────────────────────────────────

const RealismConfig: React.FC = () => {
  const { push } = useToast();
  const [config, setConfig] = useState<ConfigPayload>(DEFAULTS);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchConfig = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<ConfigPayload>('/realism/config');
      setConfig(res.data);
    } catch (err: any) {
      setError(err?.response?.status === 401 ? 'Authentication required.' : 'Load failed.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchConfig(); }, []);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await api.put<ConfigPayload>('/realism/config', config);
      setConfig(res.data);
      push({ text: 'REALISM CONFIG SAVED', tone: 'matrix', icon: 'terminal' });
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      const status = err?.response?.status;
      if (status === 403) setError('Admin role required to save.');
      else if (status === 400 && detail) setError(`Validation failed: ${detail}`);
      else setError('Save failed.');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    if (!window.confirm('Reset to baked-in defaults? This will overwrite the current saved config on next save.')) return;
    setConfig(DEFAULTS);
  };

  return (
    <div style={{ padding: '24px', color: 'var(--text-color)', maxWidth: '900px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
        <Sliders size={18} />
        <h2 style={{ margin: 0, fontSize: '1.1rem', letterSpacing: '0.05em' }}>REALISM CONFIG</h2>
      </div>
      <p style={{ color: 'var(--dim-color)', fontSize: '0.85rem', marginTop: 0 }}>
        Operator-tuned planner weights. The orchestrator refreshes from the DB
        every ~5 minutes; saved changes land within one refresh window.
      </p>

      {error && <div style={{ color: '#ff5555', marginBottom: '12px' }}>{error}</div>}

      {loading ? (
        <div style={{ opacity: 0.6 }}>Loading…</div>
      ) : (
        <>
          <WeightTable
            title="USER CLASS WEIGHTS · written by personas during work hours"
            weights={config.user_class_weights}
            onChange={(next) => setConfig({ ...config, user_class_weights: next })}
          />
          <WeightTable
            title="SYSTEM CLASS WEIGHTS · plausible OS-side filler"
            weights={config.system_class_weights}
            onChange={(next) => setConfig({ ...config, system_class_weights: next })}
          />
          <WeightTable
            title="CANARY CLASS WEIGHTS · uniform across generators by default"
            weights={config.canary_class_weights}
            onChange={(next) => setConfig({ ...config, canary_class_weights: next })}
          />

          <div style={{ marginBottom: '24px' }}>
            <div style={{
              fontSize: '0.7rem', color: 'var(--dim-color)', letterSpacing: '0.1em',
              marginBottom: '8px',
            }}>
              CANARY PROBABILITY · share of file picks that materialise a canary
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <input
                type="range"
                min={0}
                max={1}
                step={0.005}
                value={config.canary_probability}
                onChange={(e) => setConfig({
                  ...config,
                  canary_probability: parseFloat(e.target.value),
                })}
                style={{ flex: 1 }}
              />
              <span className="mono" style={{ minWidth: '60px', textAlign: 'right' }}>
                {(config.canary_probability * 100).toFixed(1)}%
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className="action-btn"
              onClick={handleSave}
              disabled={saving}
              style={{
                padding: '8px 16px',
                display: 'inline-flex', alignItems: 'center', gap: 6,
                color: 'var(--matrix)',
                borderColor: 'var(--matrix)',
                opacity: saving ? 0.5 : 1,
              }}
              title="Persist current values to realism_config; orchestrator picks them up within one refresh tick."
            >
              <Save size={12} />
              {saving ? 'SAVING…' : 'SAVE'}
            </button>
            <button
              className="action-btn"
              onClick={handleReset}
              style={{
                padding: '8px 16px',
                display: 'inline-flex', alignItems: 'center', gap: 6,
              }}
              title="Reset form fields to baked-in defaults (does not save until you press SAVE)"
            >
              <RotateCcw size={12} />
              RESET TO DEFAULTS
            </button>
          </div>
        </>
      )}
    </div>
  );
};

export default RealismConfig;
