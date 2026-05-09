import React from 'react';
import { Pencil, Trash2 } from '../../icons';
import type { EmailPersona } from './types';

interface Props {
  persona: EmailPersona;
  onEdit: () => void;
  onRemove: () => void;
}

const PersonaCard: React.FC<Props> = ({ persona: p, onEdit, onRemove }) => (
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

export default PersonaCard;
