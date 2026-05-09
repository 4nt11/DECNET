import React from 'react';
import { Save, X } from '../../icons';
import type { FormState, SimpleEvent } from './types';

interface Props {
  title: string;
  form: FormState;
  setForm: React.Dispatch<React.SetStateAction<FormState>>;
  onSave: (e: React.FormEvent) => void;
  onCancel: () => void;
  saving: boolean;
  isEdit: boolean;
  onToggleSimple: (n: SimpleEvent) => void;
}

const FormRow: React.FC<Props> = ({
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

export default FormRow;
