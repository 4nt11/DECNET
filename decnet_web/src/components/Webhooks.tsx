// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useMemo, useState } from 'react';
import {
  Plus, Trash2, Pencil, Zap, AlertTriangle, X,
  Check, Webhook as WebhookIcon,
} from '../icons';
import { useToast } from './Toasts/useToast';
import FormRow from './Webhooks/FormRow';
import SecretModal from './Webhooks/SecretModal';
import { useWebhooks } from './Webhooks/useWebhooks';
import {
  BLANK_FORM, deriveSimpleEvents, formatDate, formToPayload, SIMPLE_PRESETS,
} from './Webhooks/helpers';
import type { FormState, SimpleEvent, WebhookRow } from './Webhooks/types';
import './Dashboard.css';
import './Config.css';
import './Webhooks.css';

const Webhooks: React.FC = () => {
  const { push } = useToast();
  const {
    webhooks, loading, error,
    createWebhook, updateWebhook, removeWebhook, testWebhook,
  } = useWebhooks();

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
    const payload = formToPayload(form);
    if (form.simple_events.length === 0 && payload.topic_patterns.length === 0) {
      push({ text: 'SELECT AT LEAST ONE EVENT OR PATTERN', tone: 'violet', icon: 'alert-triangle' });
      return;
    }
    setSaving(true);
    try {
      if (editingId) {
        const r = await updateWebhook(editingId, payload);
        if (r.ok) {
          push({ text: 'WEBHOOK UPDATED', tone: 'violet', icon: 'check-circle' });
          closeForm();
        } else {
          push({ text: `SAVE FAILED · ${(r.reason ?? '').toUpperCase()}`, tone: 'violet', icon: 'alert-triangle' });
        }
      } else {
        const r = await createWebhook(payload);
        if (r.ok) {
          push({ text: 'WEBHOOK CREATED', tone: 'violet', icon: 'check-circle' });
          if (r.data?.secret) {
            setNewSecret({ name: r.data.name, secret: r.data.secret });
          }
          closeForm();
        } else {
          push({ text: `SAVE FAILED · ${(r.reason ?? '').toUpperCase()}`, tone: 'violet', icon: 'alert-triangle' });
        }
      }
    } finally {
      setSaving(false);
    }
  };

  const handleTestOne = async (uuid: string, name: string) => {
    const r = await testWebhook(uuid);
    if (!r.ok) {
      push({ text: `TEST FAILED · ${(r.reason ?? '').toUpperCase()}`, tone: 'violet', icon: 'alert-triangle' });
      return;
    }
    const { delivered, status_code, error: err } = r.data ?? { delivered: false };
    if (delivered) {
      push({ text: `${name.toUpperCase()} · DELIVERED · ${status_code}`, tone: 'violet', icon: 'zap' });
    } else {
      push({ text: `${name.toUpperCase()} · FAILED · ${(err || 'unknown').toUpperCase()}`, tone: 'violet', icon: 'alert-triangle' });
    }
  };

  const handleDeleteOne = async (uuid: string, name: string) => {
    const r = await removeWebhook(uuid);
    if (r.ok) {
      push({ text: `${name.toUpperCase()} · DELETED`, tone: 'violet', icon: 'trash' });
      setSelected((s) => {
        const n = new Set(s); n.delete(uuid); return n;
      });
    } else {
      push({ text: `DELETE FAILED · ${(r.reason ?? '').toUpperCase()}`, tone: 'violet', icon: 'alert-triangle' });
    }
  };

  const handleDeleteSelected = async () => {
    const ids = Array.from(selected);
    const results = await Promise.allSettled(ids.map((id) => removeWebhook(id)));
    const ok = results.filter((r) => r.status === 'fulfilled' && r.value.ok).length;
    const bad = results.length - ok;
    push({
      text: bad === 0 ? `DELETED · ${ok}` : `DELETED · ${ok} · FAILED · ${bad}`,
      tone: 'violet',
      icon: bad ? 'alert-triangle' : 'trash',
    });
    setSelected(new Set());
    setDeleteArmed(false);
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
                      <td className="wh-url-cell" title={w.url}>{w.url}</td>
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

export default Webhooks;
