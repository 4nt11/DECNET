import React, { useEffect, useMemo, useState } from 'react';
import api from '../utils/api';
import { useToast } from './Toasts/useToast';

export interface ServiceConfigFieldDTO {
  key: string;
  label: string;
  type: 'string' | 'password' | 'int' | 'bool' | 'textarea' | 'enum';
  default?: unknown;
  secret?: boolean;
  help?: string | null;
  enum?: string[] | null;
  placeholder?: string | null;
}

interface SchemaResponse {
  name: string;
  ports: number[];
  fleet_singleton: boolean;
  fields: ServiceConfigFieldDTO[];
}

interface Props {
  /** Decky the service runs on. */
  deckyName: string;
  /** Service slug, e.g. "ssh". */
  serviceSlug: string;
  /** Topology id when this is a MazeNET decky; omit / null for fleet. */
  topologyId?: string | null;
  /** Currently-persisted service_config[serviceSlug] from the parent. */
  currentConfig?: Record<string, unknown>;
  /** Fired after a successful PUT or apply, with the post-validation cfg. */
  onApplied?: (cfg: Record<string, unknown>, recreated: boolean) => void;
}

type FormValue = string | number | boolean;
type FormState = Record<string, FormValue>;

function toFormValue(field: ServiceConfigFieldDTO, raw: unknown): FormValue {
  if (raw === undefined || raw === null) {
    if (field.type === 'bool') return Boolean(field.default);
    if (field.type === 'int') return field.default == null ? '' as unknown as number : Number(field.default);
    return (field.default as string | undefined) ?? '';
  }
  if (field.type === 'bool') return Boolean(raw);
  if (field.type === 'int') return Number(raw);
  return String(raw);
}

function buildInitial(
  fields: ServiceConfigFieldDTO[], current: Record<string, unknown>,
): FormState {
  const out: FormState = {};
  for (const f of fields) out[f.key] = toFormValue(f, current[f.key]);
  return out;
}

const fmtError = (err: unknown, fallback: string): string =>
  (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
  ?? fallback;

const ServiceConfigForm: React.FC<Props> = ({
  deckyName, serviceSlug, topologyId, currentConfig, onApplied,
}) => {
  const { push } = useToast();
  const [schema, setSchema] = useState<SchemaResponse | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>({});
  const [initial, setInitial] = useState<FormState>({});
  const [busy, setBusy] = useState<'save' | 'apply' | null>(null);
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});

  useEffect(() => {
    let cancelled = false;
    setSchema(null);
    setLoadErr(null);
    api.get<SchemaResponse>(`/topologies/services/${encodeURIComponent(serviceSlug)}/schema`)
      .then(({ data }) => {
        if (cancelled) return;
        setSchema(data);
        const init = buildInitial(data.fields, currentConfig ?? {});
        setForm(init);
        setInitial(init);
      })
      .catch((err) => {
        if (cancelled) return;
        setLoadErr(fmtError(err, 'Schema load failed.'));
      });
    return () => { cancelled = true; };
  }, [serviceSlug, currentConfig]);

  const dirty = useMemo(() => {
    const keys = new Set([...Object.keys(form), ...Object.keys(initial)]);
    for (const k of keys) if (form[k] !== initial[k]) return true;
    return false;
  }, [form, initial]);

  const buildPayload = (): Record<string, unknown> => {
    if (!schema) return {};
    const out: Record<string, unknown> = {};
    for (const f of schema.fields) {
      const v = form[f.key];
      // Skip empty strings on optional fields — server-side validate_cfg
      // drops them anyway, but sending them risks surprising users when
      // the round-trip echoes a missing key.
      if (v === '' || v === undefined || v === null) continue;
      out[f.key] = v;
    }
    return out;
  };

  const baseUrl = topologyId
    ? `/topologies/${encodeURIComponent(topologyId)}/deckies/${encodeURIComponent(deckyName)}/services/${encodeURIComponent(serviceSlug)}`
    : `/deckies/${encodeURIComponent(deckyName)}/services/${encodeURIComponent(serviceSlug)}`;

  const save = async () => {
    if (busy) return;
    setBusy('save');
    try {
      const { data } = await api.put<{ config: Record<string, unknown>; recreated: boolean }>(
        `${baseUrl}/config`, { config: buildPayload() },
      );
      const next = buildInitial(schema!.fields, data.config);
      setForm(next);
      setInitial(next);
      onApplied?.(data.config, false);
      push({ text: `${serviceSlug} config saved (no restart).`, tone: 'matrix' });
    } catch (err) {
      push({ text: fmtError(err, 'Save failed.'), tone: 'alert' });
    } finally {
      setBusy(null);
    }
  };

  const apply = async () => {
    if (busy) return;
    const ok = window.confirm(
      `Apply ${serviceSlug} config on ${deckyName}?\n\n` +
      `This force-recreates the ${deckyName}-${serviceSlug} container so the new ` +
      'env takes effect. In-container session state on this service is lost.',
    );
    if (!ok) return;
    setBusy('apply');
    try {
      const { data } = await api.post<{ config: Record<string, unknown>; recreated: boolean }>(
        `${baseUrl}/apply`, { config: buildPayload() },
      );
      const next = buildInitial(schema!.fields, data.config);
      setForm(next);
      setInitial(next);
      onApplied?.(data.config, true);
      push({ text: `${serviceSlug} applied — container recreated.`, tone: 'matrix' });
    } catch (err) {
      push({ text: fmtError(err, 'Apply failed.'), tone: 'alert' });
    } finally {
      setBusy(null);
    }
  };

  if (loadErr) {
    return <div className="alert-text" style={{ fontSize: '0.7rem' }}>{loadErr}</div>;
  }
  if (!schema) {
    return <div className="dim" style={{ fontSize: '0.7rem' }}>Loading schema…</div>;
  }
  if (schema.fields.length === 0) {
    return (
      <div className="dim" style={{ fontSize: '0.7rem', fontStyle: 'italic' }}>
        No customizable fields for {schema.name}.
      </div>
    );
  }

  return (
    <div className="service-config-form">
      {schema.fields.map((f) => {
        const id = `svc-cfg-${deckyName}-${serviceSlug}-${f.key}`;
        const value = form[f.key];
        const setVal = (v: FormValue) => setForm((s) => ({ ...s, [f.key]: v }));
        const help = f.help ? <div className="dim svc-cfg-help">{f.help}</div> : null;
        return (
          <div key={f.key} className="svc-cfg-row">
            <label htmlFor={id} className="svc-cfg-label">
              {f.label}
              {f.secret && <span className="dim svc-cfg-secret-tag"> · secret</span>}
            </label>
            {f.type === 'bool' ? (
              <input
                id={id}
                type="checkbox"
                checked={Boolean(value)}
                onChange={(e) => setVal(e.target.checked)}
              />
            ) : f.type === 'enum' ? (
              <select
                id={id}
                value={String(value ?? '')}
                onChange={(e) => setVal(e.target.value)}
                className="svc-cfg-input"
              >
                <option value="">—</option>
                {(f.enum ?? []).map((opt) => (
                  <option key={opt} value={opt}>{opt}</option>
                ))}
              </select>
            ) : f.type === 'textarea' ? (
              <textarea
                id={id}
                value={String(value ?? '')}
                onChange={(e) => setVal(e.target.value)}
                placeholder={f.placeholder ?? ''}
                rows={3}
                className="svc-cfg-input"
              />
            ) : f.type === 'password' ? (
              <div className="svc-cfg-pw-wrap">
                <input
                  id={id}
                  type={revealed[f.key] ? 'text' : 'password'}
                  value={String(value ?? '')}
                  onChange={(e) => setVal(e.target.value)}
                  placeholder={f.placeholder ?? ''}
                  className="svc-cfg-input"
                />
                <button
                  type="button"
                  className="btn small"
                  onClick={() => setRevealed((s) => ({ ...s, [f.key]: !s[f.key] }))}
                >
                  {revealed[f.key] ? 'HIDE' : 'SHOW'}
                </button>
              </div>
            ) : (
              <input
                id={id}
                type={f.type === 'int' ? 'number' : 'text'}
                value={String(value ?? '')}
                onChange={(e) =>
                  setVal(f.type === 'int' && e.target.value !== ''
                    ? Number(e.target.value)
                    : e.target.value)}
                placeholder={f.placeholder ?? ''}
                className="svc-cfg-input"
              />
            )}
            {help}
          </div>
        );
      })}
      <div className="svc-cfg-actions">
        {dirty && <span className="dim svc-cfg-dirty-tag">UNSAVED</span>}
        <button
          type="button"
          className="btn small"
          disabled={!dirty || !!busy}
          onClick={save}
        >
          {busy === 'save' ? 'SAVING…' : 'SAVE'}
        </button>
        <button
          type="button"
          className="btn violet small"
          disabled={!!busy}
          onClick={apply}
          title="Persist + force-recreate the service container."
        >
          {busy === 'apply' ? 'APPLYING…' : 'APPLY'}
        </button>
      </div>
    </div>
  );
};

export default ServiceConfigForm;
