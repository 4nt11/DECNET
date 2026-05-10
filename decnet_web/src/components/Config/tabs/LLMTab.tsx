import React, { useEffect, useState } from 'react';
import { Save, CheckCircle } from '../../../icons';
import api from '../../../utils/api';

interface LLMPayload {
  provider: string;
  base_url: string | null;
  model: string;
  timeout: number;
  api_key_set: boolean;
}

interface PutBody {
  provider?: string;
  base_url?: string | null;
  model?: string;
  timeout?: number;
  api_key?: string;
}

const DEFAULTS: LLMPayload = {
  provider: 'ollama',
  base_url: null,
  model: 'llama3.1',
  timeout: 60,
  api_key_set: false,
};

const _SENTINEL = Symbol();

interface Props {
  isAdmin: boolean;
}

export const LLMTab: React.FC<Props> = ({ isAdmin }) => {
  const [cfg, setCfg] = useState<LLMPayload>(DEFAULTS);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [clearApiKey, setClearApiKey] = useState(false);

  useEffect(() => {
    api.get<LLMPayload>('/realism/llm')
      .then((r) => setCfg(r.data))
      .catch(() => setMsg({ type: 'error', text: 'FAILED TO LOAD LLM CONFIG' }))
      .finally(() => setLoading(false));
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setMsg(null);
    const body: PutBody = {
      provider: cfg.provider,
      base_url: cfg.base_url || null,
      model: cfg.model,
      timeout: cfg.timeout,
    };
    if (clearApiKey) body.api_key = '';
    else if (apiKeyInput.trim()) body.api_key = apiKeyInput.trim();

    try {
      const r = await api.put<LLMPayload>('/realism/llm', body);
      setCfg(r.data);
      setApiKeyInput('');
      setClearApiKey(false);
      setMsg({ type: 'success', text: 'LLM CONFIG SAVED' });
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      const status = err?.response?.status;
      if (status === 403) setMsg({ type: 'error', text: 'ADMIN ROLE REQUIRED' });
      else if (status === 400 && detail) setMsg({ type: 'error', text: `VALIDATION FAILED: ${detail}` });
      else setMsg({ type: 'error', text: 'SAVE FAILED' });
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <div className="config-panel"><span className="config-label">LOADING…</span></div>;
  }

  return (
    <div className="config-panel">
      <div className="config-field">
        <span className="config-label">PROVIDER</span>
        {isAdmin ? (
          <select
            className="role-select"
            style={{ width: 200 }}
            value={cfg.provider}
            onChange={(e) => setCfg({ ...cfg, provider: e.target.value })}
          >
            <option value="ollama">Ollama</option>
          </select>
        ) : (
          <span className="config-value">{cfg.provider}</span>
        )}
      </div>

      <div className="config-field">
        <span className="config-label">BASE URL</span>
        {isAdmin ? (
          <>
            <div className="config-input-row">
              <input
                type="url"
                style={{ width: 340 }}
                placeholder="http://127.0.0.1:11434 — blank for local subprocess"
                value={cfg.base_url || ''}
                onChange={(e) => setCfg({ ...cfg, base_url: e.target.value || null })}
              />
            </div>
            <span className="interval-hint">
              Leave blank to use local Ollama subprocess. Set to the daemon URL when targeting a remote host.
            </span>
          </>
        ) : (
          <span className="config-value">{cfg.base_url || '(subprocess)'}</span>
        )}
      </div>

      <div className="config-field">
        <span className="config-label">MODEL</span>
        {isAdmin ? (
          <div className="config-input-row">
            <input
              type="text"
              style={{ width: 200 }}
              placeholder="llama3.1"
              value={cfg.model}
              onChange={(e) => setCfg({ ...cfg, model: e.target.value })}
            />
          </div>
        ) : (
          <span className="config-value">{cfg.model}</span>
        )}
      </div>

      <div className="config-field">
        <span className="config-label">TIMEOUT (seconds)</span>
        {isAdmin ? (
          <div className="config-input-row">
            <input
              type="number"
              min={1}
              step={1}
              style={{ width: 120 }}
              value={cfg.timeout}
              onChange={(e) => {
                const v = parseFloat(e.target.value);
                if (v > 0) setCfg({ ...cfg, timeout: v });
              }}
            />
          </div>
        ) : (
          <span className="config-value">{cfg.timeout}s</span>
        )}
      </div>

      {isAdmin && (
        <div className="config-field">
          <span className="config-label">API KEY (write-only)</span>
          {cfg.api_key_set && !clearApiKey ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: 6 }}>
                <CheckCircle size={12} /> Key stored
              </span>
              <button
                className="action-btn"
                onClick={() => { setClearApiKey(true); setApiKeyInput(''); }}
              >
                CLEAR
              </button>
            </div>
          ) : (
            <div className="config-input-row">
              <input
                type="password"
                style={{ width: 280 }}
                placeholder={clearApiKey
                  ? '(will be cleared on save)'
                  : 'Enter key to set — blank keeps existing'}
                value={apiKeyInput}
                disabled={clearApiKey}
                onChange={(e) => setApiKeyInput(e.target.value)}
              />
              {clearApiKey && (
                <button className="action-btn" onClick={() => setClearApiKey(false)}>
                  CANCEL
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {isAdmin && (
        <div className="config-field" style={{ marginBottom: 0 }}>
          <div className="config-input-row">
            <button
              className="save-btn"
              onClick={handleSave}
              disabled={saving}
            >
              <Save size={14} />
              {saving ? 'SAVING...' : 'SAVE'}
            </button>
          </div>
          {msg && (
            <span className={msg.type === 'success' ? 'config-success' : 'config-error'}>
              {msg.text}
            </span>
          )}
        </div>
      )}

      {!isAdmin && (
        <div className="config-field" style={{ marginBottom: 0 }}>
          <span className="config-label">API KEY</span>
          <span className="config-value">{cfg.api_key_set ? '••••••••' : '(not set)'}</span>
        </div>
      )}
    </div>
  );
};
