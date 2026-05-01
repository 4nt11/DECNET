import React, { useEffect, useMemo, useState } from 'react';
import api from '../../utils/api';
import { useToast } from '../Toasts/useToast';
import { Save, RotateCcw, AlertTriangle, Sliders } from '../../icons';
import { contentClassLabel, isCanaryClass } from '../../realism/labels';
// Reuse the DeckyFleet shell (page-header / btn / fleet-* / dim / mono) and
// the persona-page tweaks (info-banner, .input) so the realism config panel
// reads the same as the rest of the realism nav group.
import '../DeckyFleet.css';
import '../PersonaGeneration.css';
import './RealismConfig.css';

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
    { content_class: 'canary_fingerprint_html', weight: 1 },
    { content_class: 'canary_fingerprint_svg', weight: 1 },
  ],
  canary_probability: 0.03,
};

// ─── Subcomponent ────────────────────────────────────────────────────────────

const WeightTable: React.FC<{
  title: string;
  help: string;
  weights: WeightEntry[];
  onChange: (next: WeightEntry[]) => void;
}> = ({ title, help, weights, onChange }) => {
  const total = weights.reduce((s, w) => s + Math.max(0, w.weight), 0);
  return (
    <>
      <div className="section-head">
        <span>{title}</span>
        <span className="total">TOTAL {total}</span>
      </div>
      <div className="section-help">{help}</div>
      <table className="weight-table">
        <tbody>
          {weights.map((w, i) => {
            const canary = isCanaryClass(w.content_class);
            const share =
              total === 0
                ? '—'
                : `${((Math.max(0, w.weight) / total) * 100).toFixed(1)}%`;
            return (
              <tr key={w.content_class}>
                <td className={`cls${canary ? ' canary' : ''}`}>
                  <span className="cls-label">{contentClassLabel(w.content_class)}</span>
                  <span className="cls-enum">{w.content_class}</span>
                </td>
                <td className="weight">
                  <input
                    type="number"
                    min={0}
                    step={1}
                    className="weight-input"
                    value={w.weight}
                    onChange={(e) => {
                      const v = parseInt(e.target.value, 10);
                      const next = weights.slice();
                      next[i] = {
                        ...next[i],
                        weight: Number.isFinite(v) ? Math.max(0, v) : 0,
                      };
                      onChange(next);
                    }}
                  />
                </td>
                <td className="share">{share}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
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
    if (!window.confirm(
      'Reset to baked-in defaults? This will overwrite the saved config on next save.',
    )) return;
    setConfig(DEFAULTS);
  };

  const totals = useMemo(() => ({
    user: config.user_class_weights.reduce((s, w) => s + Math.max(0, w.weight), 0),
    system: config.system_class_weights.reduce((s, w) => s + Math.max(0, w.weight), 0),
    canary: config.canary_class_weights.reduce((s, w) => s + Math.max(0, w.weight), 0),
  }), [config]);

  return (
    <div className="fleet-root realism-config-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Sliders size={22} className="violet-accent" />
            <h1>REALISM CONFIG</h1>
          </div>
          <span className="page-sub">
            USER {totals.user} · SYSTEM {totals.system} · CANARY {totals.canary} ·
            {' '}CANARY PROB {(config.canary_probability * 100).toFixed(1)}%
          </span>
        </div>
        <div className="actions">
          <button
            className="btn ghost"
            onClick={handleReset}
            disabled={saving || loading}
            title="Reset form fields to baked-in defaults (does not save until you press SAVE)"
          >
            <RotateCcw size={12} /> RESET
          </button>
          <button
            className="btn violet"
            onClick={handleSave}
            disabled={saving || loading}
            title="Persist current values to realism_config; orchestrator picks them up within one refresh tick (~5 min)."
          >
            <Save size={12} /> {saving ? 'SAVING…' : 'SAVE'}
          </button>
        </div>
      </div>

      <div className="info-banner">
        <div>
          <strong>Scope:</strong> tunes the orchestrator's <em>realism planner</em>
          {' '}— how often each kind of synthetic file lands on a decky, and
          how rare canary plants are. Persisted in the{' '}
          <span className="mono matrix-text">realism_config</span> table; the
          orchestrator refreshes from the DB every ~5 minutes.
        </div>
        {error && (
          <div className="info-line alert-text" style={{ marginTop: 8 }}>
            <AlertTriangle size={12} /> {error}
          </div>
        )}
      </div>

      {loading ? (
        <div className="dim" style={{ padding: '24px 0' }}>Loading…</div>
      ) : (
        <>
          <WeightTable
            title="User Class Weights"
            help="Files written by personas during their work hours. The realism win when a persona looks busy."
            weights={config.user_class_weights}
            onChange={(next) => setConfig({ ...config, user_class_weights: next })}
          />
          <WeightTable
            title="System Class Weights"
            help="Plausible OS-side filler — rotated logs, daemon noise, ephemeral cache."
            weights={config.system_class_weights}
            onChange={(next) => setConfig({ ...config, system_class_weights: next })}
          />
          <WeightTable
            title="Canary Class Weights"
            help="Callback-bearing artifacts. Uniform across generators by default; raise one to bias toward a specific bait flavour."
            weights={config.canary_class_weights}
            onChange={(next) => setConfig({ ...config, canary_class_weights: next })}
          />

          <div className="section-head">
            <span>Canary Probability</span>
            <span className="total">{(config.canary_probability * 100).toFixed(1)}%</span>
          </div>
          <div className="section-help">
            Share of file picks that materialise a canary. Each plant
            creates a real canary token row + DNS slug or HTTP URL —
            keeping this rare prevents a noisy alert surface.
          </div>
          <div className="prob-row">
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
            />
            <span className="prob-value">
              {(config.canary_probability * 100).toFixed(1)}%
            </span>
          </div>
        </>
      )}
    </div>
  );
};

export default RealismConfig;
