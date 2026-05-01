import React, { useEffect, useMemo, useState } from 'react';
import api, { type ApiError } from '../utils/api';
import './ServiceConfigForm.css';

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

export interface SchemaResponse {
  name: string;
  ports: number[];
  fleet_singleton: boolean;
  fields: ServiceConfigFieldDTO[];
}

export type FormValue = string | number | boolean;
export type FormState = Record<string, FormValue>;

export function toFormValue(field: ServiceConfigFieldDTO, raw: unknown): FormValue {
  if (raw === undefined || raw === null) {
    if (field.type === 'bool') return Boolean(field.default);
    if (field.type === 'int') return field.default == null ? ('' as unknown as number) : Number(field.default);
    return (field.default as string | undefined) ?? '';
  }
  if (field.type === 'bool') return Boolean(raw);
  if (field.type === 'int') return Number(raw);
  return String(raw);
}

export function buildInitial(
  fields: ServiceConfigFieldDTO[], current: Record<string, unknown>,
): FormState {
  const out: FormState = {};
  for (const f of fields) out[f.key] = toFormValue(f, current[f.key]);
  return out;
}

/** Strip empty strings, null, undefined — server's validate_cfg drops
 *  them anyway and the wizard wants a tight payload. */
export function compactPayload(
  fields: ServiceConfigFieldDTO[], state: FormState,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    const v = state[f.key];
    if (v === '' || v === undefined || v === null) continue;
    out[f.key] = v;
  }
  return out;
}

export const fmtSchemaError = (err: unknown, fallback: string): string =>
  (err as ApiError)?.response?.data?.detail
  ?? fallback;

interface Props {
  serviceSlug: string;
  /** Current values keyed by field.key.  Held by the parent. */
  value: FormState;
  onChange: (next: FormState) => void;
  /** Optional id-prefix used to disambiguate label-for/input-id pairs
   *  when multiple instances of the same slug live on a single page. */
  idScope?: string;
  /** Surface schema metadata back to the parent (fields list etc.). */
  onSchema?: (schema: SchemaResponse) => void;
  /** Initial seed when the schema lands and the parent's value is empty. */
  seedFromDefaults?: boolean;
}

const ServiceConfigFields: React.FC<Props> = ({
  serviceSlug, value, onChange, idScope, onSchema, seedFromDefaults,
}) => {
  const [schema, setSchema] = useState<SchemaResponse | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});

  useEffect(() => {
    let cancelled = false;
    setSchema(null);
    setLoadErr(null);
    api.get<SchemaResponse>(`/topologies/services/${encodeURIComponent(serviceSlug)}/schema`)
      .then(({ data }) => {
        if (cancelled) return;
        setSchema(data);
        onSchema?.(data);
        if (seedFromDefaults && Object.keys(value).length === 0) {
          onChange(buildInitial(data.fields, {}));
        }
      })
      .catch((err) => {
        if (cancelled) return;
        setLoadErr(fmtSchemaError(err, 'Schema load failed.'));
      });
    return () => { cancelled = true; };
    // serviceSlug is the only thing that should drive a refetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serviceSlug]);

  const fields = useMemo(() => schema?.fields ?? [], [schema]);

  if (loadErr) return <div className="svc-cfg-status alert-text">{loadErr}</div>;
  if (!schema) return <div className="svc-cfg-status">Loading schema…</div>;
  if (fields.length === 0) {
    return (
      <div className="svc-cfg-status">
        No customizable fields for {schema.name}.
      </div>
    );
  }

  const setVal = (key: string, v: FormValue) => onChange({ ...value, [key]: v });

  return (
    <>
      {fields.map((f) => {
        const id = `svc-cfg-${idScope ?? serviceSlug}-${f.key}`;
        const v = value[f.key] ?? toFormValue(f, undefined);
        const help = f.help ? <div className="svc-cfg-help">{f.help}</div> : null;
        return (
          <div key={f.key} className="svc-cfg-row">
            <label htmlFor={id} className="svc-cfg-label">
              {f.label}
              {f.secret && <span className="svc-cfg-secret-tag">· secret</span>}
            </label>
            {f.type === 'bool' ? (
              <input
                id={id}
                type="checkbox"
                checked={Boolean(v)}
                onChange={(e) => setVal(f.key, e.target.checked)}
              />
            ) : f.type === 'enum' ? (
              <select
                id={id}
                value={String(v ?? '')}
                onChange={(e) => setVal(f.key, e.target.value)}
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
                value={String(v ?? '')}
                onChange={(e) => setVal(f.key, e.target.value)}
                placeholder={f.placeholder ?? ''}
                rows={3}
                className="svc-cfg-input"
              />
            ) : f.type === 'password' ? (
              <div className="svc-cfg-pw-wrap">
                <input
                  id={id}
                  type={revealed[f.key] ? 'text' : 'password'}
                  value={String(v ?? '')}
                  onChange={(e) => setVal(f.key, e.target.value)}
                  placeholder={f.placeholder ?? ''}
                  className="svc-cfg-input"
                />
                <button
                  type="button"
                  className="svc-cfg-pw-toggle"
                  onClick={() => setRevealed((s) => ({ ...s, [f.key]: !s[f.key] }))}
                >
                  {revealed[f.key] ? 'HIDE' : 'SHOW'}
                </button>
              </div>
            ) : (
              <input
                id={id}
                type={f.type === 'int' ? 'number' : 'text'}
                value={String(v ?? '')}
                onChange={(e) =>
                  setVal(
                    f.key,
                    f.type === 'int' && e.target.value !== ''
                      ? Number(e.target.value)
                      : e.target.value,
                  )
                }
                placeholder={f.placeholder ?? ''}
                className="svc-cfg-input"
              />
            )}
            {help}
          </div>
        );
      })}
    </>
  );
};

export default ServiceConfigFields;
