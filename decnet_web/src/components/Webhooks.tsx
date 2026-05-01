import React, { useEffect, useMemo, useState } from 'react';
import {
  Plus, Trash2, Pencil, Zap, AlertTriangle, Copy, X, Save,
  Check, Webhook as WebhookIcon,
} from '../icons';
import api, { type ApiError } from '../utils/api';
import { useToast } from './Toasts/useToast';
import './Dashboard.css';
import './Config.css';
import './Webhooks.css';

type SimpleEvent = 'AttackerDetail' | 'DeckyStatus' | 'SystemStatus';

// Server-side canonical expansions (mirrors decnet/webhook/enums.py). Kept
// in sync manually; this is the sugar layer, not the source of truth.
const SIMPLE_PRESETS: Record<SimpleEvent, string[]> = {
  AttackerDetail: ['attacker.>'],
  DeckyStatus: ['decky.*.state', 'decky.*.traffic'],
  SystemStatus: ['system.>'],
};

interface WebhookRow {
  uuid: string;
  name: string;
  url: string;
  topic_patterns: string[];
  enabled: boolean;
  consecutive_failures: number;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_error: string | null;
  auto_disabled_at: string | null;
  created_at: string;
  updated_at: string;
  warnings: string[];
}

interface FormState {
  name: string;
  url: string;
  secret: string;                 // blank = server auto-generates (create) / keep existing (edit)
  simple_events: SimpleEvent[];
  topic_patterns: string;         // textarea: one per line
  enabled: boolean;
}

const BLANK_FORM: FormState = {
  name: '',
  url: '',
  secret: '',
  simple_events: [],
  topic_patterns: '',
  enabled: true,
};

function extractErrorDetail(err: unknown, fallback: string): string {
  const e = err as ApiError;
  if (e?.response?.data?.detail) return e.response.data.detail;
  if (e?.response?.status === 403) return 'Insufficient permissions (admin only)';
  if (e?.response?.status === 401) return 'Session expired — please log in again';
  if (e?.message) return e.message;
  return fallback;
}

/** Derive which simple-event checkboxes should show as ticked for a given
 *  persisted pattern list. Only ticks when the intersection is exact —
 *  mixed custom + preset leaves everything unticked and the textarea is
 *  the source of truth. */
function deriveSimpleEvents(patterns: string[]): SimpleEvent[] {
  const ticked: SimpleEvent[] = [];
  const remaining = new Set(patterns);
  for (const [name, preset] of Object.entries(SIMPLE_PRESETS) as [SimpleEvent, string[]][]) {
    if (preset.every((p) => remaining.has(p))) {
      ticked.push(name);
      preset.forEach((p) => remaining.delete(p));
    }
  }
  // If anything outside the presets remains, don't tick — user sees raw.
  if (remaining.size > 0) return [];
  return ticked;
}

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const Webhooks: React.FC = () => {
  const [webhooks, setWebhooks] = useState<WebhookRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { push } = useToast();

  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>(BLANK_FORM);
  const [saving, setSaving] = useState(false);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [deleteArmed, setDeleteArmed] = useState(false);

  const [newSecret, setNewSecret] = useState<{ name: string; secret: string } | null>(null);

  const insecureCount = useMemo(
    () => webhooks.filter((w) => w.warnings.some((msg) => msg.startsWith('insecure_url'))).length,
    [webhooks],
  );

  const enabledCount = useMemo(() => webhooks.filter((w) => w.enabled).length, [webhooks]);
  const failCount = useMemo(
    () => webhooks.filter((w) => w.consecutive_failures > 0).length,
    [webhooks],
  );
  const trippedCount = useMemo(
    () => webhooks.filter((w) => w.auto_disabled_at).length,
    [webhooks],
  );

  const fetchWebhooks = async () => {
    try {
      const res = await api.get('/webhooks/');
      setWebhooks(res.data);
      setError(null);
    } catch (err) {
      setError(extractErrorDetail(err, 'Failed to load webhooks'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchWebhooks();
  }, []);

  const closeForm = () => {
    setCreating(false);
    setEditingId(null);
    setForm(BLANK_FORM);
  };

  const openCreate = () => {
    setEditingId(null);
    setForm(BLANK_FORM);
    setCreating(true);
  };

  const openEdit = (w: WebhookRow) => {
    setCreating(false);
    setEditingId(w.uuid);
    const ticked = deriveSimpleEvents(w.topic_patterns);
    const remaining = ticked.length
      ? w.topic_patterns.filter((p) =>
          !ticked.some((s) => SIMPLE_PRESETS[s].includes(p)))
      : w.topic_patterns;
    setForm({
      name: w.name,
      url: w.url,
      secret: '',
      simple_events: ticked,
      topic_patterns: remaining.join('\n'),
      enabled: w.enabled,
    });
  };

  const toggleSimpleEvent = (name: SimpleEvent) => {
    setForm((f) => ({
      ...f,
      simple_events: f.simple_events.includes(name)
        ? f.simple_events.filter((s) => s !== name)
        : [...f.simple_events, name],
    }));
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim() || !form.url.trim()) return;
    const rawPatterns = form.topic_patterns
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    if (form.simple_events.length === 0 && rawPatterns.length === 0) {
      push({ text: 'SELECT AT LEAST ONE EVENT OR PATTERN', tone: 'violet', icon: 'alert-triangle' });
      return;
    }

    setSaving(true);
    try {
      if (editingId) {
        await api.patch(`/webhooks/${editingId}`, {
          name: form.name.trim(),
          url: form.url.trim(),
          secret: form.secret ? form.secret : undefined,
          simple_events: form.simple_events,
          topic_patterns: rawPatterns,
          enabled: form.enabled,
        });
        push({ text: 'WEBHOOK UPDATED', tone: 'violet', icon: 'check-circle' });
      } else {
        const res = await api.post('/webhooks/', {
          name: form.name.trim(),
          url: form.url.trim(),
          secret: form.secret ? form.secret : undefined,
          simple_events: form.simple_events,
          topic_patterns: rawPatterns,
          enabled: form.enabled,
        });
        push({ text: 'WEBHOOK CREATED', tone: 'violet', icon: 'check-circle' });
        if (res.data?.secret) {
          setNewSecret({ name: res.data.name, secret: res.data.secret });
        }
      }
      closeForm();
      await fetchWebhooks();
    } catch (err) {
      const msg = extractErrorDetail(err, 'Save failed');
      push({ text: `SAVE FAILED · ${msg.toUpperCase()}`, tone: 'violet', icon: 'alert-triangle' });
    } finally {
      setSaving(false);
    }
  };

  const handleTestOne = async (uuid: string, name: string) => {
    try {
      const res = await api.post(`/webhooks/${uuid}/test`);
      const { delivered, status_code, error: err } = res.data;
      if (delivered) {
        push({ text: `${name.toUpperCase()} · DELIVERED · ${status_code}`, tone: 'violet', icon: 'zap' });
      } else {
        push({ text: `${name.toUpperCase()} · FAILED · ${(err || 'unknown').toUpperCase()}`, tone: 'violet', icon: 'alert-triangle' });
      }
      fetchWebhooks();
    } catch (err) {
      const msg = extractErrorDetail(err, 'Test failed');
      push({ text: `TEST FAILED · ${msg.toUpperCase()}`, tone: 'violet', icon: 'alert-triangle' });
    }
  };

  const handleDeleteOne = async (uuid: string, name: string) => {
    try {
      await api.delete(`/webhooks/${uuid}`);
      push({ text: `${name.toUpperCase()} · DELETED`, tone: 'violet', icon: 'trash' });
      setSelected((s) => {
        const n = new Set(s);
        n.delete(uuid);
        return n;
      });
      fetchWebhooks();
    } catch (err) {
      const msg = extractErrorDetail(err, 'Delete failed');
      push({ text: `DELETE FAILED · ${msg.toUpperCase()}`, tone: 'violet', icon: 'alert-triangle' });
    }
  };

  const handleDeleteSelected = async () => {
    const ids = Array.from(selected);
    const results = await Promise.allSettled(ids.map((id) => api.delete(`/webhooks/${id}`)));
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const bad = results.length - ok;
    push({
      text: bad === 0
        ? `DELETED · ${ok}`
        : `DELETED · ${ok} · FAILED · ${bad}`,
      tone: 'violet',
      icon: bad ? 'alert-triangle' : 'trash',
    });
    setSelected(new Set());
    setDeleteArmed(false);
    fetchWebhooks();
  };

  const toggleSelect = (uuid: string) => {
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(uuid)) n.delete(uuid);
      else n.add(uuid);
      return n;
    });
  };

  const toggleSelectAll = () => {
    if (selected.size === webhooks.length) setSelected(new Set());
    else setSelected(new Set(webhooks.map((w) => w.uuid)));
  };

  return (
    <div className="webhooks-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <WebhookIcon size={22} className="violet-accent" />
            <h1>WEBHOOKS</h1>
          </div>
          <span className="page-sub">
            {webhooks.length} CONFIGURED · {enabledCount} ENABLED
            {trippedCount > 0 && ` · ${trippedCount} TRIPPED`}
            {failCount > 0 && ` · ${failCount} FAILING`}
            {insecureCount > 0 && ` · ${insecureCount} INSECURE`}
          </span>
        </div>
        <div className="actions">
          {selected.size > 0 && (
            deleteArmed ? (
              <>
                <button className="btn alert" onClick={handleDeleteSelected}>
                  <Check size={12} /> CONFIRM DELETE {selected.size}
                </button>
                <button className="btn ghost" onClick={() => setDeleteArmed(false)}>
                  <X size={12} /> CANCEL
                </button>
              </>
            ) : (
              <button className="btn warn" onClick={() => setDeleteArmed(true)}>
                <Trash2 size={12} /> DELETE SELECTED ({selected.size})
              </button>
            )
          )}
          <button
            className="btn violet"
            onClick={openCreate}
            disabled={creating || editingId !== null}
          >
            <Plus size={12} /> CREATE WEBHOOK
          </button>
        </div>
      </div>

      {error && <div className="config-error webhooks-error">{error}</div>}

      {insecureCount > 0 && !error && (
        <div className="webhooks-warning-banner">
          <AlertTriangle size={14} />
          <span>
            {insecureCount === 1
              ? '1 WEBHOOK USING HTTP:// — EVENT BODIES TRAVEL PLAINTEXT. HMAC STILL DETECTS TAMPERING.'
              : `${insecureCount} WEBHOOKS USING HTTP:// — EVENT BODIES TRAVEL PLAINTEXT. HMAC STILL DETECTS TAMPERING.`}
          </span>
        </div>
      )}

      <div className="logs-section">
        <div className="section-header">
          <div className="section-title">
            <WebhookIcon size={14} />
            <span>SUBSCRIPTIONS</span>
          </div>
          <div className="section-actions">
            <span>SHOWING {webhooks.length}</span>
          </div>
        </div>

        {loading ? (
          <div className="webhooks-empty">LOADING WEBHOOKS…</div>
        ) : webhooks.length === 0 && !creating ? (
          <div className="webhooks-empty">
            NO WEBHOOKS CONFIGURED — CLICK CREATE WEBHOOK TO ADD ONE.
          </div>
        ) : (
          <div className="webhooks-table-wrap">
            <table className="webhooks-table users-table">
              <thead>
                <tr>
                  <th className="col-check">
                    <input
                      type="checkbox"
                      checked={webhooks.length > 0 && selected.size === webhooks.length}
                      onChange={toggleSelectAll}
                    />
                  </th>
                  <th>NAME</th>
                  <th>URL</th>
                  <th>PATTERNS</th>
                  <th>STATUS</th>
                  <th>LAST FIRED</th>
                  <th className="col-actions">ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {creating && (
                  <FormRow
                    title="NEW WEBHOOK"
                    form={form}
                    setForm={setForm}
                    onSave={handleSave}
                    onCancel={closeForm}
                    saving={saving}
                    isEdit={false}
                    onToggleSimple={toggleSimpleEvent}
                  />
                )}
                {webhooks.map((w) => (
                  editingId === w.uuid ? (
                    <FormRow
                      key={w.uuid}
                      title={`EDIT · ${w.name.toUpperCase()}`}
                      form={form}
                      setForm={setForm}
                      onSave={handleSave}
                      onCancel={closeForm}
                      saving={saving}
                      isEdit
                      onToggleSimple={toggleSimpleEvent}
                    />
                  ) : (
                    <tr key={w.uuid}>
                      <td className="col-check">
                        <input
                          type="checkbox"
                          checked={selected.has(w.uuid)}
                          onChange={() => toggleSelect(w.uuid)}
                        />
                      </td>
                      <td>{w.name}</td>
                      <td className="wh-url-cell" title={w.url}>
                        {w.url}
                      </td>
                      <td>
                        {w.topic_patterns.slice(0, 2).map((p) => (
                          <span key={p} className="wh-chip">{p}</span>
                        ))}
                        {w.topic_patterns.length > 2 && (
                          <span className="wh-chip" title={w.topic_patterns.slice(2).join(', ')}>
                            +{w.topic_patterns.length - 2}
                          </span>
                        )}
                      </td>
                      <td>
                        <span className={`wh-chip ${w.enabled ? '' : 'status-disabled'}`}>
                          {w.enabled ? 'ENABLED' : 'DISABLED'}
                        </span>
                        {w.auto_disabled_at && (
                          <span
                            className="wh-chip status-fail"
                            title={`Circuit tripped at ${formatDate(w.auto_disabled_at)}. Re-enable via Edit to reset.`}
                          >
                            TRIPPED · {formatDate(w.auto_disabled_at)}
                          </span>
                        )}
                        {w.consecutive_failures > 0 && (
                          <span className="wh-chip status-fail" title={w.last_error || ''}>
                            FAIL · {w.consecutive_failures}
                          </span>
                        )}
                        {w.warnings.some((m) => m.startsWith('insecure_url')) && (
                          <span className="wh-chip status-warn" title="URL uses http://">
                            HTTP
                          </span>
                        )}
                      </td>
                      <td>{formatDate(w.last_success_at)}</td>
                      <td>
                        <div className="wh-actions">
                          <button
                            className="action-btn fire"
                            onClick={() => handleTestOne(w.uuid, w.name)}
                            title="Fire a synthetic test event to this webhook (POST /webhooks/{uuid}/test)"
                          >
                            <Zap size={12} />
                            FIRE
                          </button>
                          <button
                            className="action-btn"
                            onClick={() => openEdit(w)}
                            title="Edit"
                            disabled={creating || editingId !== null}
                          >
                            <Pencil size={12} />
                          </button>
                          <button
                            className="action-btn danger"
                            onClick={() => handleDeleteOne(w.uuid, w.name)}
                            title="Delete"
                          >
                            <Trash2 size={12} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {newSecret && (
        <SecretModal
          name={newSecret.name}
          secret={newSecret.secret}
          onClose={() => setNewSecret(null)}
        />
      )}
    </div>
  );
};

interface FormRowProps {
  title: string;
  form: FormState;
  setForm: React.Dispatch<React.SetStateAction<FormState>>;
  onSave: (e: React.FormEvent) => void;
  onCancel: () => void;
  saving: boolean;
  isEdit: boolean;
  onToggleSimple: (n: SimpleEvent) => void;
}

const FormRow: React.FC<FormRowProps> = ({
  title, form, setForm, onSave, onCancel, saving, isEdit, onToggleSimple,
}) => (
  <tr className="wh-form-row">
    <td colSpan={7}>
      <form className="wh-form-grid" onSubmit={onSave}>
        <label className="wh-form-title">{title}</label>

        <label>NAME</label>
        <input
          type="text"
          value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          placeholder="shuffle-prod"
          required
          maxLength={64}
        />

        <label>URL</label>
        <input
          type="url"
          value={form.url}
          onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
          placeholder="https://shuffle.example.com/api/v1/hooks/webhook_xxx"
          required
        />

        <label>
          SECRET {isEdit && <span className="wh-form-hint">(blank = keep existing)</span>}
        </label>
        <input
          type="password"
          value={form.secret}
          onChange={(e) => setForm((f) => ({ ...f, secret: e.target.value }))}
          placeholder={isEdit ? '—' : 'leave blank to auto-generate'}
          minLength={16}
          maxLength={256}
        />

        <label>SIMPLE EVENTS</label>
        <div className="wh-checkbox-group">
          {(['AttackerDetail', 'DeckyStatus', 'SystemStatus'] as const).map((name) => (
            <label key={name}>
              <input
                type="checkbox"
                checked={form.simple_events.includes(name)}
                onChange={() => onToggleSimple(name)}
              />
              {name}
            </label>
          ))}
        </div>

        <label>
          ADVANCED PATTERNS
          <br />
          <span className="wh-form-hint">(one per line, NATS-style)</span>
        </label>
        <textarea
          value={form.topic_patterns}
          onChange={(e) => setForm((f) => ({ ...f, topic_patterns: e.target.value }))}
          placeholder={'attacker.>\ndecky.*.state'}
        />

        <label>ENABLED</label>
        <div className="wh-checkbox-group">
          <label>
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
            />
            Receive events
          </label>
        </div>

        <div className="wh-form-buttons">
          <button type="button" className="btn ghost" onClick={onCancel} disabled={saving}>
            <X size={12} /> CANCEL
          </button>
          <button type="submit" className="btn violet" disabled={saving}>
            <Save size={12} /> {saving ? 'SAVING…' : isEdit ? 'SAVE CHANGES' : 'CREATE'}
          </button>
        </div>
      </form>
    </td>
  </tr>
);

interface SecretModalProps {
  name: string;
  secret: string;
  onClose: () => void;
}

const SecretModal: React.FC<SecretModalProps> = ({ name, secret, onClose }) => {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* no-op — browsers without clipboard perms will just see no feedback */
    }
  };
  return (
    <div
      className="wh-secret-modal-backdrop"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="wh-secret-modal">
        <h3>WEBHOOK SECRET · {name.toUpperCase()}</h3>
        <div className="wh-secret-warn">
          <AlertTriangle size={14} />
          <span>COPY THIS NOW — IT WILL NOT BE SHOWN AGAIN. THE HMAC ON EVERY DELIVERY IS SIGNED WITH THIS VALUE.</span>
        </div>
        <div className="wh-secret-value">{secret}</div>
        <div className="wh-secret-actions">
          <button className="btn ghost" onClick={copy}>
            <Copy size={12} /> {copied ? 'COPIED' : 'COPY'}
          </button>
          <button className="btn violet" onClick={onClose}>
            <Check size={12} /> DONE
          </button>
        </div>
      </div>
    </div>
  );
};

export default Webhooks;
