import React, { useMemo, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import {
  Mail, Plus, AlertTriangle, Upload, Download, Sparkles,
} from '../icons';
import { useToast } from './Toasts/useToast';
import PersonaCard from './PersonaGeneration/PersonaCard';
import PersonaEditor from './PersonaGeneration/PersonaEditor';
import { usePersonaGeneration } from './PersonaGeneration/usePersonaGeneration';
import {
  BLANK, TEMPLATE, coercePersona, mergePersonas, validate,
} from './PersonaGeneration/helpers';
import type { EmailPersona, FilterKey } from './PersonaGeneration/types';
import './DeckyFleet.css';
import './PersonaGeneration.css';

interface Props {
  /** When set, the editor manages the personas attached to the given
   *  topology row (Topology.email_personas) instead of the global
   *  fleet/SWARM pool.  The component negotiates this with two
   *  backend endpoints sharing the same wire shape. */
  topologyId?: string;
}

const PersonaGeneration: React.FC<Props> = ({ topologyId }) => {
  const { push } = useToast();
  const isTopology = Boolean(topologyId);
  const data = usePersonaGeneration(topologyId);
  const {
    personas, path, topoName, languageDefault, loading, error, setError,
    persistPersonas,
  } = data;

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

  /** Thin wrapper over the data-hook persist: handles toast/announce
   *  policy here since the hook itself stays UI-free. */
  const persist = async (next: EmailPersona[], successText: string): Promise<boolean> => {
    const r = await persistPersonas(next);
    if (r.ok) {
      push({ text: successText, tone: 'matrix', icon: 'check' });
      return true;
    }
    push({ text: (r.reason ?? 'Failed').toUpperCase(), tone: 'alert', icon: 'alert-triangle' });
    return false;
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
    const ok = await persist(
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
    await persist(
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
      void persist(merged, summary).then((ok) => {
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
