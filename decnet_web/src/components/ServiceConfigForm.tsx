import React, { useMemo, useState } from 'react';
import api from '../utils/api';
import { useToast } from './Toasts/useToast';
import ServiceConfigFields, {
  type FormState,
  type SchemaResponse,
  buildInitial,
  compactPayload,
  fmtSchemaError,
} from './ServiceConfigFields';
import './ServiceConfigForm.css';

export type { ServiceConfigFieldDTO } from './ServiceConfigFields';

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

const ServiceConfigForm: React.FC<Props> = ({
  deckyName, serviceSlug, topologyId, currentConfig, onApplied,
}) => {
  const { push } = useToast();
  const [schema, setSchema] = useState<SchemaResponse | null>(null);
  const [form, setForm] = useState<FormState>({});
  const [initial, setInitial] = useState<FormState>({});
  const [busy, setBusy] = useState<'save' | 'apply' | null>(null);

  // Reseed form values when currentConfig changes meaningfully (by JSON
  // identity, not reference — parents pass fresh `{}` literals).
  const seedKey = useMemo(() => JSON.stringify(currentConfig ?? {}), [currentConfig]);
  React.useEffect(() => {
    if (!schema) return;
    const init = buildInitial(schema.fields, currentConfig ?? {});
    setForm(init);
    setInitial(init);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [schema, seedKey]);

  const dirty = useMemo(() => {
    const keys = new Set([...Object.keys(form), ...Object.keys(initial)]);
    for (const k of keys) if (form[k] !== initial[k]) return true;
    return false;
  }, [form, initial]);

  const baseUrl = topologyId
    ? `/topologies/${encodeURIComponent(topologyId)}/deckies/${encodeURIComponent(deckyName)}/services/${encodeURIComponent(serviceSlug)}`
    : `/deckies/${encodeURIComponent(deckyName)}/services/${encodeURIComponent(serviceSlug)}`;

  const save = async () => {
    if (busy || !schema) return;
    setBusy('save');
    try {
      const { data } = await api.put<{ config: Record<string, unknown>; recreated: boolean }>(
        `${baseUrl}/config`, { config: compactPayload(schema.fields, form) },
      );
      const next = buildInitial(schema.fields, data.config);
      setForm(next);
      setInitial(next);
      onApplied?.(data.config, false);
      push({ text: `${serviceSlug} config saved (no restart).`, tone: 'matrix' });
    } catch (err) {
      push({ text: fmtSchemaError(err, 'Save failed.'), tone: 'alert' });
    } finally {
      setBusy(null);
    }
  };

  const apply = async () => {
    if (busy || !schema) return;
    const ok = window.confirm(
      `Apply ${serviceSlug} config on ${deckyName}?\n\n` +
      `This force-recreates the ${deckyName}-${serviceSlug} container so the new ` +
      'env takes effect. In-container session state on this service is lost.',
    );
    if (!ok) return;
    setBusy('apply');
    try {
      const { data } = await api.post<{ config: Record<string, unknown>; recreated: boolean }>(
        `${baseUrl}/apply`, { config: compactPayload(schema.fields, form) },
      );
      const next = buildInitial(schema.fields, data.config);
      setForm(next);
      setInitial(next);
      onApplied?.(data.config, true);
      push({ text: `${serviceSlug} applied — container recreated.`, tone: 'matrix' });
    } catch (err) {
      push({ text: fmtSchemaError(err, 'Apply failed.'), tone: 'alert' });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="service-config-form">
      <ServiceConfigFields
        serviceSlug={serviceSlug}
        value={form}
        onChange={setForm}
        idScope={`${deckyName}-${serviceSlug}`}
        onSchema={setSchema}
      />
      {schema && schema.fields.length > 0 && (
        <div className="svc-cfg-actions">
          {dirty && <span className="svc-cfg-dirty-tag">UNSAVED</span>}
          <button
            type="button"
            className="svc-cfg-btn"
            disabled={!dirty || !!busy}
            onClick={save}
          >
            {busy === 'save' ? 'SAVING…' : 'SAVE'}
          </button>
          <button
            type="button"
            className="svc-cfg-btn violet"
            disabled={!!busy}
            onClick={apply}
            title="Persist + force-recreate the service container."
          >
            {busy === 'apply' ? 'APPLYING…' : 'APPLY'}
          </button>
        </div>
      )}
    </div>
  );
};

export default ServiceConfigForm;
