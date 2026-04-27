import React, { useEffect, useMemo, useState } from 'react';
import {
  Mail, Plus, Pencil, Trash2, Save, X, Check, AlertTriangle,
} from '../icons';
import api from '../utils/api';
import { useToast } from './Toasts/useToast';
import EmptyState from './EmptyState/EmptyState';
import './PersonaGeneration.css';

type Tone = 'formal' | 'direct' | 'casual' | 'technical';
type ReplyLatency = 'fast' | 'normal' | 'slow';

interface EmailPersona {
  name: string;
  email: string;
  role: string;
  tone: Tone;
  mannerisms: string[];
  language: string | null;
  signature: string | null;
  active_hours: string;
  reply_latency: ReplyLatency;
  uses_llms_heavily: boolean;
}

interface PersonasResponse {
  path: string;
  personas: EmailPersona[];
}

const BLANK: EmailPersona = {
  name: '',
  email: '',
  role: '',
  tone: 'formal',
  mannerisms: [],
  language: 'en',
  signature: null,
  active_hours: '09:00-18:00',
  reply_latency: 'normal',
  uses_llms_heavily: false,
};

const TONES: Tone[] = ['formal', 'direct', 'casual', 'technical'];
const LATENCIES: ReplyLatency[] = ['fast', 'normal', 'slow'];

function extractErrorDetail(err: unknown, fallback: string): string {
  const e = err as {
    response?: { status?: number; data?: { detail?: string } };
    message?: string;
  };
  if (e?.response?.data?.detail) return e.response.data.detail;
  if (e?.response?.status === 403) return 'Insufficient permissions (admin only)';
  if (e?.response?.status === 401) return 'Session expired — please log in again';
  if (e?.message) return e.message;
  return fallback;
}

/** Light client-side validation — server re-validates with the same
 *  Pydantic schema the worker uses, this is just the early-warn UX. */
function validate(p: EmailPersona): string | null {
  if (!p.name.trim()) return 'name is required';
  if (!p.email.trim()) return 'email is required';
  if (!p.email.includes('@') || !p.email.split('@')[1]?.includes('.')) {
    return 'email must look like user@domain.tld';
  }
  if (!p.role.trim()) return 'role is required';
  if (p.mannerisms.length > 12) return 'at most 12 mannerisms per persona';
  return null;
}

const PersonaGeneration: React.FC = () => {
  const { push } = useToast();

  const [path, setPath] = useState<string>('');
  const [personas, setPersonas] = useState<EmailPersona[]>([]);
  const [serverPersonas, setServerPersonas] = useState<EmailPersona[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [modalOpen, setModalOpen] = useState(false);
  const [editingIdx, setEditingIdx] = useState<number | null>(null);
  const [draft, setDraft] = useState<EmailPersona>(BLANK);
  const [draftError, setDraftError] = useState<string | null>(null);
  const [mannerismDraft, setMannerismDraft] = useState('');

  const dirty = useMemo(
    () => JSON.stringify(personas) !== JSON.stringify(serverPersonas),
    [personas, serverPersonas],
  );

  const fetchPersonas = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<PersonasResponse>('/emailgen/personas');
      const list = res.data.personas ?? [];
      setPersonas(list);
      setServerPersonas(list);
      setPath(res.data.path ?? '');
    } catch (err) {
      setError(extractErrorDetail(err, 'Failed to load personas'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPersonas();
  }, []);

  const openAdd = () => {
    setEditingIdx(null);
    setDraft({ ...BLANK });
    setMannerismDraft('');
    setDraftError(null);
    setModalOpen(true);
  };

  const openEdit = (idx: number) => {
    setEditingIdx(idx);
    setDraft({ ...personas[idx] });
    setMannerismDraft('');
    setDraftError(null);
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setDraft(BLANK);
    setEditingIdx(null);
    setMannerismDraft('');
    setDraftError(null);
  };

  const saveDraft = () => {
    const err = validate(draft);
    if (err) {
      setDraftError(err);
      return;
    }
    // Email uniqueness — same address across two personas would let
    // the scheduler pick "John" as both sender and recipient.
    const dupeIdx = personas.findIndex(
      (p, i) => p.email === draft.email && i !== editingIdx,
    );
    if (dupeIdx !== -1) {
      setDraftError(`email already used by "${personas[dupeIdx].name}"`);
      return;
    }
    if (editingIdx === null) {
      setPersonas([...personas, draft]);
    } else {
      const next = personas.slice();
      next[editingIdx] = draft;
      setPersonas(next);
    }
    closeModal();
  };

  const removePersona = (idx: number) => {
    if (!confirm(`Remove ${personas[idx].name}?`)) return;
    setPersonas(personas.filter((_, i) => i !== idx));
  };

  const addMannerism = () => {
    const t = mannerismDraft.trim();
    if (!t) return;
    if (draft.mannerisms.includes(t)) {
      setMannerismDraft('');
      return;
    }
    setDraft({ ...draft, mannerisms: [...draft.mannerisms, t] });
    setMannerismDraft('');
  };

  const removeMannerism = (idx: number) => {
    setDraft({
      ...draft,
      mannerisms: draft.mannerisms.filter((_, i) => i !== idx),
    });
  };

  const saveAll = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await api.put<PersonasResponse>('/emailgen/personas', {
        personas,
      });
      const list = res.data.personas ?? [];
      setPersonas(list);
      setServerPersonas(list);
      setPath(res.data.path ?? path);
      push({
        text: `SAVED ${list.length} PERSONA${list.length === 1 ? '' : 'S'}`,
        tone: 'matrix',
        icon: 'check',
      });
    } catch (err) {
      const msg = extractErrorDetail(err, 'Failed to save personas');
      setError(msg);
      push({ text: msg.toUpperCase(), tone: 'alert', icon: 'alert-triangle' });
    } finally {
      setSaving(false);
    }
  };

  const discardChanges = () => {
    if (!dirty) return;
    if (!confirm('Discard unsaved changes?')) return;
    setPersonas(serverPersonas);
  };

  return (
    <div className="persona-gen-root">
      <div className="page-header">
        <div className="page-title-group">
          <div className="header-line">
            <Mail size={22} className="violet-accent" />
            <h1>PERSONA GENERATION</h1>
            {dirty && (
              <span className="dirty-pill">
                <AlertTriangle size={12} />
                UNSAVED CHANGES
              </span>
            )}
          </div>
          <span className="page-sub">
            GLOBAL POOL · FLEET (MACVLAN/IPVLAN) + SWARM-SHARD MAIL DECKIES
          </span>
        </div>
      </div>

      <div className="info-banner">
        <div>
          <strong>Scope:</strong> personas listed here drive emailgen against{' '}
          <em>non-MazeNET</em> mail deckies (unihost MACVLAN/IPVLAN, SWARM
          shards). MazeNET topologies have their own per-topology persona
          list configured in the topology editor.
        </div>
        {path && (
          <div className="info-line">
            <span className="dim">FILE</span>{' '}
            <span className="mono matrix-text">{path}</span>
          </div>
        )}
      </div>

      <div className="controls-row">
        <button className="btn primary" onClick={openAdd}>
          <Plus size={12} />
          ADD PERSONA
        </button>
        <button
          className="btn"
          onClick={saveAll}
          disabled={!dirty || saving}
        >
          <Save size={12} />
          {saving ? 'SAVING…' : 'SAVE CHANGES'}
        </button>
        <button
          className="btn ghost"
          onClick={discardChanges}
          disabled={!dirty || saving}
        >
          DISCARD
        </button>
        {error && (
          <span className="error-line">
            <AlertTriangle size={12} /> {error}
          </span>
        )}
      </div>

      <div className="persona-list">
        {loading ? (
          <EmptyState icon={Mail} title="LOADING…" />
        ) : personas.length === 0 ? (
          <EmptyState
            icon={Mail}
            title="NO PERSONAS CONFIGURED"
            hint="add at least 2 to start the emailgen worker against fleet/shard mail deckies"
          />
        ) : (
          <table className="persona-table">
            <thead>
              <tr>
                <th>NAME</th>
                <th>EMAIL</th>
                <th>ROLE</th>
                <th>TONE</th>
                <th>LANG</th>
                <th>HOURS</th>
                <th>REPLY</th>
                <th>MANNERISMS</th>
                <th>FLAGS</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {personas.map((p, idx) => (
                <tr key={`${p.email}-${idx}`}>
                  <td>{p.name}</td>
                  <td className="mono">{p.email}</td>
                  <td>{p.role}</td>
                  <td>
                    <span className={`tone-chip tone-${p.tone}`}>{p.tone}</span>
                  </td>
                  <td>
                    <span className="chip dim-chip">
                      {(p.language ?? 'en').toUpperCase()}
                    </span>
                  </td>
                  <td className="mono">{p.active_hours}</td>
                  <td>{p.reply_latency}</td>
                  <td className="dim">
                    {p.mannerisms.length === 0
                      ? '—'
                      : `${p.mannerisms.length} item${p.mannerisms.length === 1 ? '' : 's'}`}
                  </td>
                  <td>
                    {p.uses_llms_heavily && (
                      <span
                        className="chip warn-chip"
                        title="Em-dash suppression lifted for this persona"
                      >
                        LLM-HEAVY
                      </span>
                    )}
                  </td>
                  <td className="row-actions">
                    <button
                      className="icon-btn"
                      onClick={() => openEdit(idx)}
                      aria-label={`Edit ${p.name}`}
                    >
                      <Pencil size={14} />
                    </button>
                    <button
                      className="icon-btn danger"
                      onClick={() => removePersona(idx)}
                      aria-label={`Remove ${p.name}`}
                    >
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modalOpen && (
        <div
          className="persona-modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeModal();
          }}
        >
          <div className="persona-modal">
            <div className="bd-head">
              <h3>
                <Mail size={14} />
                {editingIdx === null ? 'ADD PERSONA' : 'EDIT PERSONA'}
              </h3>
              <button
                className="close-btn"
                onClick={closeModal}
                aria-label="Close"
              >
                <X size={16} />
              </button>
            </div>
            <div className="bd-body">
              <label className="field">
                <span className="field-label">NAME *</span>
                <input
                  type="text"
                  value={draft.name}
                  onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                  placeholder="John Smith"
                />
              </label>

              <label className="field">
                <span className="field-label">EMAIL *</span>
                <input
                  type="email"
                  value={draft.email}
                  onChange={(e) => setDraft({ ...draft, email: e.target.value })}
                  placeholder="john.smith@corp.com"
                />
              </label>

              <label className="field">
                <span className="field-label">ROLE *</span>
                <input
                  type="text"
                  value={draft.role}
                  onChange={(e) => setDraft({ ...draft, role: e.target.value })}
                  placeholder="Chief Operating Officer"
                />
              </label>

              <div className="field-row">
                <label className="field">
                  <span className="field-label">TONE</span>
                  <select
                    value={draft.tone}
                    onChange={(e) => setDraft({ ...draft, tone: e.target.value as Tone })}
                  >
                    {TONES.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </label>

                <label className="field">
                  <span className="field-label">LANGUAGE</span>
                  <input
                    type="text"
                    maxLength={8}
                    value={draft.language ?? ''}
                    onChange={(e) =>
                      setDraft({ ...draft, language: e.target.value || null })
                    }
                    placeholder="en"
                  />
                </label>

                <label className="field">
                  <span className="field-label">REPLY LATENCY</span>
                  <select
                    value={draft.reply_latency}
                    onChange={(e) =>
                      setDraft({
                        ...draft,
                        reply_latency: e.target.value as ReplyLatency,
                      })
                    }
                  >
                    {LATENCIES.map((l) => (
                      <option key={l} value={l}>{l}</option>
                    ))}
                  </select>
                </label>
              </div>

              <label className="field">
                <span className="field-label">ACTIVE HOURS</span>
                <input
                  type="text"
                  value={draft.active_hours}
                  onChange={(e) =>
                    setDraft({ ...draft, active_hours: e.target.value })
                  }
                  placeholder="09:00-18:00 (wraps OK e.g. 22:00-06:00)"
                />
              </label>

              <label className="field">
                <span className="field-label">MANNERISMS (≤12)</span>
                <div className="mannerism-input-row">
                  <input
                    type="text"
                    value={mannerismDraft}
                    onChange={(e) => setMannerismDraft(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        addMannerism();
                      }
                    }}
                    placeholder="opens with 'Hey' not 'Dear'"
                  />
                  <button
                    type="button"
                    className="btn ghost"
                    onClick={addMannerism}
                    disabled={!mannerismDraft.trim() || draft.mannerisms.length >= 12}
                  >
                    <Plus size={12} /> ADD
                  </button>
                </div>
                <ul className="mannerism-list">
                  {draft.mannerisms.map((m, i) => (
                    <li key={i}>
                      <span>{m}</span>
                      <button
                        type="button"
                        className="icon-btn danger"
                        onClick={() => removeMannerism(i)}
                        aria-label={`Remove mannerism ${i + 1}`}
                      >
                        <X size={12} />
                      </button>
                    </li>
                  ))}
                </ul>
              </label>

              <label className="field">
                <span className="field-label">SIGNATURE (optional)</span>
                <textarea
                  rows={3}
                  value={draft.signature ?? ''}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      signature: e.target.value || null,
                    })
                  }
                  placeholder="-- John&#10;COO, ACME Corp"
                />
              </label>

              <label className="field check-field">
                <input
                  type="checkbox"
                  checked={draft.uses_llms_heavily}
                  onChange={(e) =>
                    setDraft({ ...draft, uses_llms_heavily: e.target.checked })
                  }
                />
                <span>
                  <strong>Uses LLMs heavily</strong>
                  <span className="dim">
                    {' — em-dash suppression lifted; this persona’s output may '}
                    contain natural em-dashes.
                  </span>
                </span>
              </label>

              {draftError && (
                <div className="draft-error">
                  <AlertTriangle size={12} /> {draftError}
                </div>
              )}
            </div>
            <div className="bd-actions">
              <button className="btn ghost" onClick={closeModal}>
                CANCEL
              </button>
              <button className="btn primary" onClick={saveDraft}>
                <Check size={12} />
                {editingIdx === null ? 'ADD' : 'UPDATE'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PersonaGeneration;
