// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import { Mail, Plus, Check, AlertTriangle } from '../../icons';
import Modal from '../Modal/Modal';
import { LATENCIES, TONES } from './helpers';
import type { EmailPersona, ReplyLatency, Tone } from './types';

interface Props {
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

const PersonaEditor: React.FC<Props> = ({
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

export default PersonaEditor;
