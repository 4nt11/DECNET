import React, { useEffect, useState } from 'react';
import api from '../utils/api';
import Modal from './Modal/Modal';
import ServiceConfigFields, {
  type FormState as SvcFormState,
  type ServiceConfigFieldDTO as SvcFieldDTO,
  type SchemaResponse,
  buildInitial as svcBuildInitial,
  compactPayload as svcCompactPayload,
  fmtSchemaError,
} from './ServiceConfigFields';

interface Props {
  /** When non-null, modal is open for this {decky, slug}. */
  pending: { deckyName: string; slug: string } | null;
  /** Operator dismissed the modal without adding. */
  onCancel: () => void;
  /** User confirmed (or schema is empty — auto-confirm path). */
  onConfirm: (deckyName: string, slug: string, config: Record<string, unknown>) => Promise<void>;
}

const AddServiceConfigModal: React.FC<Props> = ({ pending, onCancel, onConfirm }) => {
  const [schema, setSchema] = useState<SchemaResponse | null>(null);
  const [state, setState] = useState<SvcFormState>({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const slug = pending?.slug ?? null;
  const deckyName = pending?.deckyName ?? null;

  // Reset on slug change so leftover state from a previous open doesn't
  // bleed through into a different service's form.
  useEffect(() => {
    setSchema(null);
    setState({});
    setBusy(false);
    setErr(null);
    if (!slug || !deckyName) return;
    let cancelled = false;
    api.get<SchemaResponse>(`/topologies/services/${encodeURIComponent(slug)}/schema`)
      .then(({ data }) => {
        if (cancelled) return;
        setSchema(data);
        // Empty schema → no operator decision to make; fire immediately
        // and close. The caller's onConfirm handles the POST.
        if (data.fields.length === 0) {
          onConfirm(deckyName, slug, {}).catch(() => { /* caller surfaces */ });
          return;
        }
        setState(svcBuildInitial(data.fields, {}));
      })
      .catch((loadErr) => {
        if (cancelled) return;
        setErr(fmtSchemaError(loadErr, 'Schema load failed.'));
      });
    return () => { cancelled = true; };
  }, [slug, deckyName, onConfirm]);

  // Don't render anything while we're auto-confirming an empty-schema add —
  // saves the brief flash of an empty modal.
  if (!pending) return null;
  if (schema && schema.fields.length === 0) return null;

  const fields: SvcFieldDTO[] = schema?.fields ?? [];

  const submit = async () => {
    if (!schema || !slug || !deckyName) return;
    setBusy(true);
    setErr(null);
    try {
      const compact = svcCompactPayload(fields, state);
      await onConfirm(deckyName, slug, compact);
    } catch (e) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
        ?? 'Add failed.';
      setErr(msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={Boolean(pending)}
      onClose={busy ? () => { /* ignore close-during-busy */ } : onCancel}
      title={slug ? `ADD ${slug.toUpperCase()}` : 'ADD SERVICE'}
      accent="violet"
      footer={
        <>
          <button type="button" className="btn small" onClick={onCancel} disabled={busy}>
            CANCEL
          </button>
          <button
            type="button"
            className="btn violet small"
            onClick={submit}
            disabled={busy || !schema}
          >
            {busy ? 'ADDING…' : 'ADD'}
          </button>
        </>
      }
    >
      <div className="modal-body">
        {!schema && !err && <div className="svc-cfg-status">Loading schema…</div>}
        {err && <div className="svc-cfg-status alert-text">{err}</div>}
        {schema && slug && fields.length > 0 && (
          <ServiceConfigFields
            serviceSlug={slug}
            value={state}
            onChange={setState}
            idScope={`add-${slug}`}
          />
        )}
      </div>
    </Modal>
  );
};

export default AddServiceConfigModal;
