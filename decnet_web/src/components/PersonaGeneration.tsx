import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import {
  Mail, Plus, Pencil, Trash2, Check, AlertTriangle, Upload, Download, Sparkles,
} from '../icons';
import api, { type ApiError } from '../utils/api';
import { useToast } from './Toasts/useToast';
import Modal from './Modal/Modal';
import './DeckyFleet.css';
import './PersonaGeneration.css';

type Tone = 'formal' | 'direct' | 'casual' | 'technical' | 'custom';
type ReplyLatency = 'fast' | 'normal' | 'slow';

interface EmailPersona {
  name: string;
  email: string;
  role: string;
  tone: Tone;
  tone_custom: string | null;
  mannerisms: string[];
  language: string | null;
  signature: string | null;
  active_hours: string;
  reply_latency: ReplyLatency;
  uses_llms_heavily: boolean;
}

interface PersonasResponse {
  path?: string;
  topology_name?: string;
  language_default?: string;
  personas: EmailPersona[];
}

const BLANK: EmailPersona = {
  name: '',
  email: '',
  role: '',
  tone: 'formal',
  tone_custom: null,
  mannerisms: [],
  language: 'en',
  signature: null,
  active_hours: '09:00-18:00',
  reply_latency: 'normal',
  uses_llms_heavily: false,
};

const TONES: Tone[] = ['formal', 'direct', 'casual', 'technical', 'custom'];
const LATENCIES: ReplyLatency[] = ['fast', 'normal', 'slow'];

type FilterKey = 'all' | Tone;

function extractErrorDetail(err: unknown, fallback: string): string {
  const e = err as ApiError;
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
  if (p.tone === 'custom' && !(p.tone_custom ?? '').trim()) {
    return 'custom tone requires a description';
  }
  if (p.mannerisms.length > 12) return 'at most 12 mannerisms per persona';
  return null;
}

// ─── Bulk upload helpers ──────────────────────────────────────────────────

const TEMPLATE: { personas: EmailPersona[] } = {
  personas: [
    {
      name: 'Jane Operator',
      email: 'jane@example.com',
      role: 'Network Admin',
      tone: 'formal',
      tone_custom: null,
      mannerisms: ["uses bullet points", "signs off with 'Best regards'"],
      language: 'en',
      signature: 'Jane Operator\nNetwork Admin',
      active_hours: '09:00-18:00',
      reply_latency: 'normal',
      uses_llms_heavily: false,
    },
  ],
};

/** Soft client-side normalizer for an uploaded persona entry.
 *  Mirrors the Pydantic rules in decnet/realism/personas.py.
 *  Server re-validates on save, so this is just early-warn UX. */
function coercePersona(raw: unknown): { ok: EmailPersona } | { error: string } {
  if (!raw || typeof raw !== 'object') return { error: 'entry is not an object' };
  const r = raw as Record<string, unknown>;
  const name = typeof r.name === 'string' ? r.name.trim() : '';
  const email = typeof r.email === 'string' ? r.email.trim() : '';
  const role = typeof r.role === 'string' ? r.role.trim() : '';
  if (!name) return { error: 'missing name' };
  if (!email) return { error: 'missing email' };
  if (!email.includes('@') || !email.split('@')[1]?.includes('.')) {
    return { error: `invalid email "${email}"` };
  }
  if (!role) return { error: 'missing role' };
  const tone = TONES.includes(r.tone as Tone) ? (r.tone as Tone) : 'formal';
  const tone_custom = typeof r.tone_custom === 'string' && r.tone_custom.trim()
    ? r.tone_custom.slice(0, 128) : null;
  if (tone === 'custom' && !tone_custom) {
    return { error: 'tone="custom" requires a non-empty tone_custom' };
  }
  const reply_latency = LATENCIES.includes(r.reply_latency as ReplyLatency)
    ? (r.reply_latency as ReplyLatency) : 'normal';
  const mannerisms = Array.isArray(r.mannerisms)
    ? r.mannerisms.filter((m): m is string => typeof m === 'string').slice(0, 12)
    : [];
  const language = typeof r.language === 'string' && r.language
    ? r.language.slice(0, 8) : null;
  const signature = typeof r.signature === 'string' && r.signature
    ? r.signature : null;
  const active_hours = typeof r.active_hours === 'string' && r.active_hours
    ? r.active_hours : '09:00-18:00';
  return {
    ok: {
      name, email, role, tone, tone_custom, mannerisms, language, signature,
      active_hours, reply_latency,
      uses_llms_heavily: r.uses_llms_heavily === true,
    },
  };
}

interface MergeResult {
  merged: EmailPersona[];
  added: number;
  replaced: number;
}

/** Dedupe by lowercased email; uploaded entries replace existing matches. */
function mergePersonas(current: EmailPersona[], incoming: EmailPersona[]): MergeResult {
  const byEmail = new Map<string, EmailPersona>();
  for (const p of current) byEmail.set(p.email.toLowerCase(), p);
  let added = 0;
  let replaced = 0;
  for (const p of incoming) {
    const key = p.email.toLowerCase();
    if (byEmail.has(key)) replaced += 1;
    else added += 1;
    byEmail.set(key, p);
  }
  return { merged: Array.from(byEmail.values()), added, replaced };
}

// ─── Persona card ─────────────────────────────────────────────────────────

interface PersonaCardProps {
  persona: EmailPersona;
  onEdit: () => void;
  onRemove: () => void;
}

const PersonaCard: React.FC<PersonaCardProps> = ({ persona: p, onEdit, onRemove }) => (
  <div className="decky-card persona-card">
    <div className="decky-head">
      <div className="decky-name">
        <span className={`status-dot ${p.uses_llms_heavily ? 'mutating' : 'active'}`} />
        {p.name}
      </div>
      <span className="decky-ip">{p.email}</span>
    </div>

    <div className="decky-meta">
      <div className="row">
        <span className="label">ROLE</span>
        <span>{p.role}</span>
      </div>
      <div className="row">
        <span className="label">TONE</span>
        <span
          className={`tone-chip tone-${p.tone}`}
          title={p.tone === 'custom' ? (p.tone_custom ?? '') : undefined}
        >
          {p.tone === 'custom' && p.tone_custom
            ? (p.tone_custom.length > 24 ? `${p.tone_custom.slice(0, 22)}…` : p.tone_custom)
            : p.tone}
        </span>
      </div>
      <div className="row">
        <span className="label">LANG</span>
        <span className="dim">{(p.language ?? 'en').toUpperCase()}</span>
      </div>
      <div className="row">
        <span className="label">HOURS</span>
        <span className="mono">{p.active_hours}</span>
      </div>
      <div className="row">
        <span className="label">REPLY</span>
        <span className="violet-accent">{p.reply_latency}</span>
      </div>
    </div>

    <div>
      <div className="type-label" style={{ marginBottom: 6, opacity: 0.5, fontSize: '0.62rem', letterSpacing: 1 }}>
        MANNERISMS
      </div>
      <div className="decky-services">
        {p.mannerisms.length === 0 ? (
          <span className="dim" style={{ fontSize: '0.7rem' }}>—</span>
        ) : (
          p.mannerisms.map((m, i) => (
            <span key={i} className="service-tag" title={m}>
              {m.length > 24 ? `${m.slice(0, 22)}…` : m}
            </span>
          ))
        )}
      </div>
    </div>

    <div className="decky-footer">
      <span className="decky-hits">
        {p.uses_llms_heavily ? (
          <span className="alert-text" style={{ fontWeight: 700 }} title="Em-dash suppression lifted">
            LLM-HEAVY
          </span>
        ) : (
          <span className="dim">SUPPRESSED EM-DASH</span>
        )}
      </span>
      <div style={{ display: 'flex', gap: 6 }}>
        <button className="btn small" onClick={onEdit} title={`Edit ${p.name}`}>
          <Pencil size={10} /> EDIT
        </button>
        <button className="btn alert small" onClick={onRemove} title={`Remove ${p.name}`}>
          <Trash2 size={10} /> REMOVE
        </button>
      </div>
    </div>
  </div>
);

// ─── Editor modal ─────────────────────────────────────────────────────────

interface PersonaEditorProps {
  open: boolean;
  editing: boolean;
  draft: EmailPersona;
  setDraft: (p: EmailPersona) => void;
  draftError: string | null;
  mannerismDraft: string;
  setMannerismDraft: (s: string) => void;
  onClose: () => void;
  onSave: () => void;
}

const PersonaEditor: React.FC<PersonaEditorProps> = ({
  open, editing, draft, setDraft, draftError,
  mannerismDraft, setMannerismDraft, onClose, onSave,
}) => {
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

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={editing ? 'EDIT PERSONA' : 'ADD PERSONA'}
      icon={Mail}
      accent="violet"
      width="wide"
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>CANCEL</button>
          <button className="btn violet" onClick={onSave}>
            <Check size={12} /> {editing ? 'UPDATE' : 'ADD'}
          </button>
        </>
      }
    >
      <div className="modal-body">
        <div className="grid-2">
          <div className="tweak-group">
            <label>NAME *</label>
            <input
              className="input"
              type="text"
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              placeholder="John Smith"
            />
          </div>
          <div className="tweak-group">
            <label>EMAIL *</label>
            <input
              className="input"
              type="email"
              value={draft.email}
              onChange={(e) => setDraft({ ...draft, email: e.target.value })}
              placeholder="john.smith@corp.com"
            />
          </div>
        </div>

        <div className="tweak-group">
          <label>ROLE *</label>
          <input
            className="input"
            type="text"
            value={draft.role}
            onChange={(e) => setDraft({ ...draft, role: e.target.value })}
            placeholder="Chief Operating Officer"
          />
        </div>

        <div className="grid-2">
          <div className="tweak-group">
            <label>TONE</label>
            <select
              className="input"
              value={draft.tone}
              onChange={(e) => setDraft({ ...draft, tone: e.target.value as Tone })}
            >
              {TONES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            {draft.tone === 'custom' && (
              <input
                className="input"
                type="text"
                maxLength={128}
                style={{ marginTop: 6 }}
                value={draft.tone_custom ?? ''}
                onChange={(e) =>
                  setDraft({ ...draft, tone_custom: e.target.value || null })
                }
                placeholder="e.g. terse, deadpan, sarcastic-but-polite"
              />
            )}
          </div>
          <div className="tweak-group">
            <label>LANGUAGE</label>
            <input
              className="input"
              type="text"
              maxLength={8}
              value={draft.language ?? ''}
              onChange={(e) => setDraft({ ...draft, language: e.target.value || null })}
              placeholder="en"
            />
          </div>
          <div className="tweak-group">
            <label>REPLY LATENCY</label>
            <select
              className="input"
              value={draft.reply_latency}
              onChange={(e) =>
                setDraft({ ...draft, reply_latency: e.target.value as ReplyLatency })
              }
            >
              {LATENCIES.map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <div className="tweak-group">
            <label>ACTIVE HOURS</label>
            <input
              className="input"
              type="text"
              value={draft.active_hours}
              onChange={(e) => setDraft({ ...draft, active_hours: e.target.value })}
              placeholder="09:00-18:00 (wraps OK)"
            />
          </div>
        </div>

        <div className="tweak-group">
          <label>MANNERISMS ({draft.mannerisms.length}/12)</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              className="input"
              type="text"
              style={{ flex: 1 }}
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
          {draft.mannerisms.length > 0 && (
            <div className="decky-services" style={{ marginTop: 8 }}>
              {draft.mannerisms.map((m, i) => (
                <span
                  key={i}
                  className="service-tag"
                  style={{ cursor: 'pointer' }}
                  onClick={() => removeMannerism(i)}
                  title="click to remove"
                >
                  {m} ✕
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="tweak-group">
          <label>SIGNATURE (optional)</label>
          <textarea
            className="input"
            rows={3}
            style={{ resize: 'vertical', fontFamily: 'var(--font-mono)' }}
            value={draft.signature ?? ''}
            onChange={(e) => setDraft({ ...draft, signature: e.target.value || null })}
            placeholder="-- John&#10;COO, ACME Corp"
          />
        </div>

        <div
          style={{
            display: 'flex', gap: 10, alignItems: 'center',
            padding: 14, border: '1px solid var(--border)',
          }}
        >
          <input
            id="llm-heavy"
            type="checkbox"
            checked={draft.uses_llms_heavily}
            onChange={(e) => setDraft({ ...draft, uses_llms_heavily: e.target.checked })}
            style={{ accentColor: 'var(--violet)' }}
          />
          <label htmlFor="llm-heavy" style={{ fontSize: '0.78rem', letterSpacing: 1 }}>
            <strong>USES LLMS HEAVILY</strong>
            <span className="dim" style={{ marginLeft: 8, letterSpacing: 0 }}>
              em-dash suppression lifted; output may contain natural em-dashes
            </span>
          </label>
        </div>

        {draftError && (
          <div
            style={{
              border: '1px solid var(--alert)',
              color: 'var(--alert)',
              padding: '8px 12px',
              fontSize: '0.75rem',
              letterSpacing: 1,
              display: 'inline-flex',
              gap: 8,
              alignItems: 'center',
            }}
          >
            <AlertTriangle size={12} /> {draftError}
          </div>
        )}
      </div>
    </Modal>
  );
};

// ─── Page ─────────────────────────────────────────────────────────────────

interface PersonaGenerationProps {
  /** When set, the editor manages the personas attached to the given
   *  topology row (Topology.email_personas) instead of the global
   *  fleet/SWARM pool.  The component negotiates this with two
   *  backend endpoints sharing the same wire shape. */
  topologyId?: string;
}

const PersonaGeneration: React.FC<PersonaGenerationProps> = ({ topologyId }) => {
  const { push } = useToast();
  const isTopology = Boolean(topologyId);
  const endpoint = isTopology
    ? `/topologies/${topologyId}/personas`
    : '/realism/personas';

  const [path, setPath] = useState<string>('');
  const [topoName, setTopoName] = useState<string>('');
  const [languageDefault, setLanguageDefault] = useState<string>('en');
  const [personas, setPersonas] = useState<EmailPersona[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<FilterKey>('all');

  const fileRef = useRef<HTMLInputElement>(null);

  const [modalOpen, setModalOpen] = useState(false);
  const [editingIdx, setEditingIdx] = useState<number | null>(null);
  const [draft, setDraft] = useState<EmailPersona>(BLANK);
  const [draftError, setDraftError] = useState<string | null>(null);
  const [mannerismDraft, setMannerismDraft] = useState('');

  const counts = useMemo(() => {
    const c: Record<FilterKey, number> = {
      all: personas.length,
      formal: 0, direct: 0, casual: 0, technical: 0, custom: 0,
    };
    for (const p of personas) c[p.tone] += 1;
    return c;
  }, [personas]);

  const visible = useMemo(
    () => filter === 'all' ? personas : personas.filter((p) => p.tone === filter),
    [personas, filter],
  );

  const fetchPersonas = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<PersonasResponse>(endpoint);
      const list = res.data.personas ?? [];
      setPersonas(list);
      setPath(res.data.path ?? '');
      setTopoName(res.data.topology_name ?? '');
      setLanguageDefault(res.data.language_default ?? 'en');
    } catch (err) {
      setError(extractErrorDetail(err, 'Failed to load personas'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchPersonas(); /* eslint-disable-next-line */ }, [endpoint]);

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

  /** PUT *next* and adopt the server's parsed result on success.
   *  Returns true if the write committed.  Persona changes are saved
   *  eagerly (no SAVE/DISCARD staging) so each CRUD action is one round-
   *  trip; on failure we leave the local list untouched so the UI never
   *  shows phantom rows. */
  const persistPersonas = async (
    next: EmailPersona[],
    successText: string,
  ): Promise<boolean> => {
    setError(null);
    try {
      const res = await api.put<PersonasResponse>(endpoint, { personas: next });
      const list = res.data.personas ?? [];
      setPersonas(list);
      setPath(res.data.path ?? path);
      setTopoName(res.data.topology_name ?? topoName);
      setLanguageDefault(res.data.language_default ?? languageDefault);
      push({ text: successText, tone: 'matrix', icon: 'check' });
      return true;
    } catch (err) {
      const msg = extractErrorDetail(err, 'Failed to save personas');
      setError(msg);
      push({ text: msg.toUpperCase(), tone: 'alert', icon: 'alert-triangle' });
      return false;
    }
  };

  const saveDraft = async () => {
    const err = validate(draft);
    if (err) { setDraftError(err); return; }
    // Email uniqueness — same address across two personas would let
    // the scheduler pick "John" as both sender and recipient.
    const dupeIdx = personas.findIndex(
      (p, i) => p.email === draft.email && i !== editingIdx,
    );
    if (dupeIdx !== -1) {
      setDraftError(`email already used by "${personas[dupeIdx].name}"`);
      return;
    }
    let next: EmailPersona[];
    if (editingIdx === null) {
      next = [...personas, draft];
    } else {
      next = personas.slice();
      next[editingIdx] = draft;
    }
    const ok = await persistPersonas(
      next,
      editingIdx === null
        ? `ADDED ${draft.name.toUpperCase()}`
        : `UPDATED ${draft.name.toUpperCase()}`,
    );
    if (ok) closeModal();
  };

  const removePersona = async (idx: number) => {
    const target = personas[idx];
    if (!confirm(`Remove ${target.name}?`)) return;
    await persistPersonas(
      personas.filter((_, i) => i !== idx),
      `REMOVED ${target.name.toUpperCase()}`,
    );
  };

  const downloadTemplate = () => {
    const blob = new Blob(
      [JSON.stringify(TEMPLATE, null, 2)],
      { type: 'application/json' },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'email_personas_template.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleBulkFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    // Reset the input so picking the same file twice still fires onChange.
    e.target.value = '';
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => {
      setError(null);
      let parsed: unknown;
      try {
        parsed = JSON.parse(String(reader.result));
      } catch (err) {
        setError(`Could not parse JSON: ${(err as Error).message}`);
        return;
      }
      // Accept either a top-level array or { personas: [...] }.
      let rawList: unknown[] | null = null;
      if (Array.isArray(parsed)) {
        rawList = parsed;
      } else if (parsed && typeof parsed === 'object'
                 && Array.isArray((parsed as { personas?: unknown }).personas)) {
        rawList = (parsed as { personas: unknown[] }).personas;
      }
      if (!rawList) {
        setError('Expected a JSON array or an object with a "personas" array');
        return;
      }
      const accepted: EmailPersona[] = [];
      const reasons: string[] = [];
      for (let i = 0; i < rawList.length; i += 1) {
        const r = coercePersona(rawList[i]);
        if ('ok' in r) accepted.push(r.ok);
        else reasons.push(`#${i + 1}: ${r.error}`);
      }
      if (accepted.length === 0) {
        setError(
          `No valid personas in ${f.name}.` +
          (reasons.length ? ` First issue: ${reasons[0]}` : ''),
        );
        return;
      }
      const { merged, added, replaced } = mergePersonas(personas, accepted);
      const skipped = reasons.length;
      const parts = [`+${added} added`];
      if (replaced) parts.push(`${replaced} replaced`);
      if (skipped) parts.push(`${skipped} skipped`);
      const summary = `IMPORTED ${accepted.length} PERSONA${accepted.length === 1 ? '' : 'S'} (${parts.join(', ')})`;
      void persistPersonas(merged, summary).then((ok) => {
        if (ok && skipped) {
          // Persisted, but show *why* some were dropped so the operator
          // can fix the source file.
          setError(`Skipped ${skipped} invalid entr${skipped === 1 ? 'y' : 'ies'}: ${reasons.slice(0, 3).join('; ')}${reasons.length > 3 ? '…' : ''}`);
        }
      });
    };
    reader.readAsText(f);
  };

  if (loading) {
    return (
      <div className="fleet-root">
        <div className="dim" style={{ padding: '40px', textAlign: 'center', letterSpacing: 2 }}>
          LOADING PERSONAS...
        </div>
      </div>
    );
  }

  const llmHeavyCount = personas.filter((p) => p.uses_llms_heavily).length;

  return (
    <div className="fleet-root persona-gen-root">
      <div className="page-header">
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Sparkles size={22} className="violet-accent" />
            <h1>{isTopology ? 'TOPOLOGY PERSONAS' : 'PERSONA GENERATION'}</h1>
          </div>
          <span className="page-sub">
            {personas.length} PERSONA{personas.length === 1 ? '' : 'S'} · {llmHeavyCount} LLM-HEAVY
            {isTopology
              ? ` · TOPOLOGY ${topoName ? topoName.toUpperCase() : (topologyId ?? '').slice(0, 8)} · DEFAULT LANG ${languageDefault.toUpperCase()}`
              : ' · GLOBAL POOL · FLEET (MACVLAN/IPVLAN) + SWARM-SHARD MAIL DECKIES'}
          </span>
        </div>
        <div className="actions">
          <div className="fleet-filter-group">
            {([['all', 'ALL'], ['formal', 'FORMAL'], ['direct', 'DIRECT'],
               ['casual', 'CASUAL'], ['technical', 'TECHNICAL'],
               ['custom', 'CUSTOM']] as [FilterKey, string][]).map(
              ([v, l]) => (
                <button
                  key={v}
                  onClick={() => setFilter(v)}
                  className={`fleet-filter-btn ${filter === v ? 'active' : ''}`}
                >
                  {l} {counts[v]}
                </button>
              ),
            )}
          </div>
          <button className="btn violet" onClick={openAdd}>
            <Plus size={12} /> ADD PERSONA
          </button>
          <input
            ref={fileRef}
            type="file"
            accept="application/json,.json"
            onChange={handleBulkFile}
            style={{ display: 'none' }}
          />
          <button
            className="btn"
            onClick={() => fileRef.current?.click()}
            title="Import personas from a JSON file"
          >
            <Upload size={12} /> BULK UPLOAD
          </button>
          <button
            className="btn ghost"
            onClick={downloadTemplate}
            title="Download a JSON template you can fill out and re-upload"
          >
            <Download size={12} /> TEMPLATE
          </button>
        </div>
      </div>

      <div className="info-banner">
        {isTopology ? (
          <div>
            <strong>Scope:</strong> personas listed here drive emailgen for the
            mail deckies attached to <em>this MazeNET topology only</em>.
            Unset <code>language</code> entries fall back to the topology's
            default ({languageDefault.toUpperCase()}).
          </div>
        ) : (
          <div>
            <strong>Scope:</strong> personas listed here drive emailgen against{' '}
            <em>non-MazeNET</em> mail deckies (unihost MACVLAN/IPVLAN, SWARM
            shards). MazeNET topologies have their own per-topology persona
            list configured in the topology editor.
          </div>
        )}
        {path && !isTopology && (
          <div className="info-line">
            <span className="dim">FILE</span>{' '}
            <span className="mono matrix-text">{path}</span>
          </div>
        )}
        {error && (
          <div className="info-line alert-text" style={{ marginTop: 8 }}>
            <AlertTriangle size={12} /> {error}
          </div>
        )}
      </div>

      <div className="grid-fleet">
        {visible.length === 0 ? (
          <div className="fleet-empty">
            <Mail size={32} className="dim" />
            <span className="dim">
              {personas.length === 0
                ? (isTopology
                    ? 'NO PERSONAS ON THIS TOPOLOGY — ADD AT LEAST 2 SO THE EMAILGEN SCHEDULER CAN PICK SENDER+RECIPIENT'
                    : 'NO PERSONAS CONFIGURED — ADD AT LEAST 2 TO START THE EMAILGEN WORKER')
                : 'NO PERSONAS MATCH CURRENT FILTER'}
            </span>
            {personas.length === 0 && (
              <button className="btn violet" onClick={openAdd}>
                <Plus size={12} /> ADD PERSONA
              </button>
            )}
          </div>
        ) : (
          visible.map((p, idx) => {
            const realIdx = personas.indexOf(p);
            return (
              <PersonaCard
                key={`${p.email}-${idx}`}
                persona={p}
                onEdit={() => openEdit(realIdx)}
                onRemove={() => removePersona(realIdx)}
              />
            );
          })
        )}
      </div>

      <PersonaEditor
        open={modalOpen}
        editing={editingIdx !== null}
        draft={draft}
        setDraft={setDraft}
        draftError={draftError}
        mannerismDraft={mannerismDraft}
        setMannerismDraft={setMannerismDraft}
        onClose={closeModal}
        onSave={saveDraft}
      />
    </div>
  );
};

export default PersonaGeneration;

// Topology-bound variant. Mounted at /topologies/:id/personas; the
// route component reads the id off the URL so callers can `<Link>`
// straight in from the topology list / MazeNET toolbar.
export const TopologyPersonaGeneration: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  if (!id) return null;
  return <PersonaGeneration topologyId={id} />;
};
