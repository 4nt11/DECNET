import React, { useEffect, useMemo, useState } from 'react';
import { PlusCircle } from '../../icons';
import api from '../../utils/api';
import Modal from '../Modal/Modal';
import { DEFAULT_SERVICES } from '../MazeNET/data';
import ServiceConfigFields, {
  type FormState as SvcFormState,
  type ServiceConfigFieldDTO as SvcFieldDTO,
  compactPayload as svcCompactPayload,
} from '../ServiceConfigFields';
import { PickIcon } from './helpers';
import type { Archetype } from './types';

interface Props {
  open: boolean;
  onClose: () => void;
  onComplete: (count: number) => void;
  archetypes: Archetype[];
  fleetSize: number;
}

type PickMode = 'archetype' | 'services';

const PLACEHOLDER_LINES = (
  archetypeName: string, services: string[], count: number, fleetSize: number,
): string[] => [
  '[INIT] allocating MAC addresses...',
  '[NET]  binding macvlan interfaces...',
  `[FP]   spoofing OS fingerprint → ${archetypeName}`,
  `[SVC]  starting services: ${services.join(', ') || '—'}`,
  '[TLS]  provisioning self-signed certs...',
  '[SENSE] attaching syslog sinks to logging stack...',
  `[OK]   ${count} deckies online — fleet size now ${fleetSize + count}`,
];

// UTF-8-safe base64 encode (btoa alone breaks on non-ASCII).
const b64encodeUtf8 = (s: string): string => {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
};

const buildIni = (
  prefix: string, count: number, fleetSize: number,
  mode: PickMode, archetype: Archetype | null, services: string[],
  mutate: boolean, mutateEvery: number,
  serviceConfigs: Record<string, Record<string, unknown>>,
  serviceSchemas: Record<string, SvcFieldDTO[]>,
): string => {
  const lines: string[] = [];
  for (let i = 0; i < count; i++) {
    const name = `${prefix}-${String(fleetSize + i + 1).padStart(2, '0')}`;
    lines.push(`[${name}]`);
    if (mode === 'archetype' && archetype) {
      lines.push(`archetype=${archetype.slug}`);
    } else if (mode === 'services' && services.length) {
      lines.push(`services=${services.join(',')}`);
    }
    if (mutate) lines.push(`mutate_interval=${mutateEvery}`);
    lines.push('');
  }
  // Per-service overrides emitted as [<prefix>.<svc>] group subsections.
  // The INI loader (decnet/ini_loader.py) prefix-matches these onto every
  // ``${prefix}-NN`` decky in the batch, so one block covers all clones.
  for (const svc of services) {
    const cfg = serviceConfigs[svc];
    if (!cfg || Object.keys(cfg).length === 0) continue;
    const fieldTypes: Record<string, SvcFieldDTO['type']> = {};
    for (const f of serviceSchemas[svc] ?? []) fieldTypes[f.key] = f.type;
    lines.push(`[${prefix}.${svc}]`);
    for (const [k, v] of Object.entries(cfg)) {
      // textarea values may contain newlines that ConfigParser can't carry
      // on a single line; wrap them in `b64:` so validate_cfg decodes back
      // to the original UTF-8 string. Other types are emitted raw.
      let serialised: string;
      if (fieldTypes[k] === 'textarea' && typeof v === 'string') {
        serialised = `b64:${b64encodeUtf8(v)}`;
      } else {
        serialised = typeof v === 'string' ? v : String(v);
      }
      lines.push(`${k}=${serialised}`);
    }
    lines.push('');
  }
  return lines.join('\n');
};

/** Multi-step deploy wizard for the fleet. Steps:
 *    0 ARCHETYPE  - pick archetype OR pick individual services
 *    1 CONFIGURATION  - prefix + count + per-service overrides
 *    2 MUTATION  - enable + interval slider
 *    3 DEPLOY  - preview command, fire POST /deckies/deploy
 */
export const DeployWizard: React.FC<Props> = ({
  open, onClose, onComplete, archetypes, fleetSize,
}) => {
  const [step, setStep] = useState(0);
  const [pickMode, setPickMode] = useState<PickMode>('archetype');
  const [archetype, setArchetype] = useState<Archetype | null>(null);
  const [selectedServices, setSelectedServices] = useState<string[]>([]);
  const [prefix, setPrefix] = useState('decky');
  const [count, setCount] = useState(3);
  const [mutate, setMutate] = useState(true);
  const [mutateEvery, setMutateEvery] = useState(30);
  const [deploying, setDeploying] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [deployErr, setDeployErr] = useState<string | null>(null);
  // Per-service config dicts keyed by service slug.  Edits flow into
  // the INI as [<decky>.<svc>] subsections at deploy time so the
  // initial container build picks them up — no follow-up apply needed.
  const [serviceConfigs, setServiceConfigs] = useState<Record<string, SvcFormState>>({});
  const [serviceSchemas, setServiceSchemas] = useState<Record<string, SvcFieldDTO[]>>({});
  const [openSvcCfg, setOpenSvcCfg] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setStep(0);
    setPickMode('archetype');
    setArchetype(null);
    setSelectedServices([]);
    setPrefix('decky');
    setCount(3);
    setMutate(true);
    setMutateEvery(30);
    setDeploying(false);
    setLog([]);
    setDeployErr(null);
    setServiceConfigs({});
    setServiceSchemas({});
    setOpenSvcCfg(null);
  }, [open]);

  const effectiveArchetypeName = archetype?.name
    ?? (pickMode === 'services' && selectedServices.length ? 'custom services' : 'linux-server');
  const effectiveServices = pickMode === 'archetype'
    ? (archetype?.services ?? [])
    : selectedServices;

  // Drop config for services no longer in the selection so the INI
  // doesn't carry orphaned subsections, and auto-collapse the open
  // panel if its service got removed.
  useEffect(() => {
    setServiceConfigs((prev) => {
      const allowed = new Set(effectiveServices);
      const next: Record<string, SvcFormState> = {};
      for (const [k, v] of Object.entries(prev)) if (allowed.has(k)) next[k] = v;
      return next;
    });
    setOpenSvcCfg((cur) => (cur && effectiveServices.includes(cur) ? cur : null));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effectiveServices.join('|')]);

  // Preview lines, count-aware (shows up to 6, with "…and N more" footer).
  const previewLines = useMemo(() => {
    const out: string[] = [];
    const cap = Math.min(count, 6);
    for (let i = 0; i < cap; i++) {
      const name = `${prefix}-${String(fleetSize + i + 1).padStart(2, '0')}`;
      out.push(`${name}  →  ${effectiveArchetypeName}  [${effectiveServices.join(', ') || '—'}]`);
    }
    if (count > 6) out.push(`...and ${count - 6} more`);
    return out;
  }, [count, prefix, fleetSize, effectiveArchetypeName, effectiveServices]);

  const [deployOk, setDeployOk] = useState(false);
  const [deployFailures, setDeployFailures] = useState<string[]>([]);

  // Fake log stream during "deploying" (runs as visual backdrop; real API
  // lines are spliced in by startDeploy once the HTTP call resolves).
  useEffect(() => {
    if (step !== 3 || !deploying) return;
    const msgs = PLACEHOLDER_LINES(effectiveArchetypeName, effectiveServices, count, fleetSize);
    let i = 0;
    const t = window.setInterval(() => {
      setLog((prev) => [...prev, msgs[i]]);
      i++;
      if (i >= msgs.length) {
        window.clearInterval(t);
        // Only auto-close if the server accepted.
        if (deployOk) {
          window.setTimeout(() => onComplete(count), 500);
        }
      }
    }, 420);
    return () => window.clearInterval(t);
  }, [step, deploying, effectiveArchetypeName, effectiveServices, count, fleetSize, onComplete, deployOk]);

  const canNext = step === 0
    ? (pickMode === 'archetype' ? !!archetype : selectedServices.length > 0)
    : true;

  const startDeploy = async () => {
    setDeployErr(null);
    setLog([]);
    setDeployOk(false);
    setDeployFailures([]);
    setDeploying(true);
    // Roll the per-service forms into the compact payload the server
    // expects — empty values dropped, types coerced where the schema
    // already pulled in primitives.
    const rolled: Record<string, Record<string, unknown>> = {};
    for (const svc of effectiveServices) {
      const fields = serviceSchemas[svc];
      const state = serviceConfigs[svc];
      if (!fields || !state) continue;
      const compact = svcCompactPayload(fields, state);
      if (Object.keys(compact).length > 0) rolled[svc] = compact;
    }
    const servicesForIni = pickMode === 'archetype'
      ? (archetype?.services ?? [])
      : selectedServices;
    const ini = buildIni(
      prefix, count, fleetSize, pickMode, archetype, servicesForIni,
      mutate, mutateEvery, rolled, serviceSchemas,
    );
    try {
      const res = await api.post<{ failures?: { name: string; reason: string }[] }>(
        '/deckies/deploy',
        { ini_content: ini },
        { timeout: 180000 },
      );
      const failures = res.data?.failures ?? [];
      setDeployFailures(failures.map(f => `[FAIL] ${f.name}: ${f.reason}`));
      if (failures.length > 0) {
        setLog(prev => [...prev, `[OK]   server accepted ${count - failures.length}/${count}`,
          ...failures.map(f => `[FAIL] ${f.name}: ${f.reason}`)]);
      } else {
        setLog(prev => [...prev, `[OK]   server accepted ${count} deckies`]);
      }
      setDeployOk(true);
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } }; message?: string };
      setDeployErr(err?.response?.data?.detail || err?.message || 'Deploy failed');
      setDeploying(false);
    }
  };

  const toggleService = (slug: string) => {
    setSelectedServices((prev) =>
      prev.includes(slug) ? prev.filter((s) => s !== slug) : [...prev, slug]);
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="DEPLOY NEW DECKIES"
      icon={PlusCircle}
      accent="violet"
      width="wide"
      footer={
        <>
          <button
            className="btn ghost"
            onClick={onClose}
            disabled={deploying && !deployOk}
          >
            {deployOk ? 'CLOSE' : 'CANCEL'}
          </button>
          <div style={{ display: 'flex', gap: 8 }}>
            {step > 0 && !deploying && (
              <button className="btn ghost" onClick={() => setStep((s) => s - 1)}>← BACK</button>
            )}
            {step < 3 && (
              <button className="btn" disabled={!canNext} onClick={() => setStep((s) => s + 1)}>
                NEXT →
              </button>
            )}
            {step === 3 && !deploying && (
              <button className="btn violet" onClick={startDeploy}>ESTABLISH FLEET</button>
            )}
            {step === 3 && deploying && !deployOk && (
              <button className="btn" disabled>DEPLOYING...</button>
            )}
            {step === 3 && deployOk && deployFailures.length > 0 && (
              <button className="btn alert" disabled>{deployFailures.length} FAILED</button>
            )}
          </div>
        </>
      }
    >
      <>
        <div className="wizard-steps">
          {['ARCHETYPE', 'CONFIGURATION', 'MUTATION', 'DEPLOY'].map((l, i) => (
            <div key={l} className={`wizard-step ${i === step ? 'active' : i < step ? 'done' : ''}`}>
              {i + 1}. {l}
            </div>
          ))}
        </div>

        <div className="modal-body">
          {step === 0 && (
            <>
              <div className="wizard-subtabs">
                <button
                  className={`wizard-subtab ${pickMode === 'archetype' ? 'active' : ''}`}
                  onClick={() => setPickMode('archetype')}
                >
                  PICK ARCHETYPE
                </button>
                <button
                  className={`wizard-subtab ${pickMode === 'services' ? 'active' : ''}`}
                  onClick={() => setPickMode('services')}
                >
                  PICK SERVICES
                </button>
              </div>
              {pickMode === 'archetype' ? (
                <>
                  <div className="type-label">Pick the archetype the deckies should masquerade as.</div>
                  <div className="pick-grid">
                    {archetypes.map((a) => (
                      <button
                        key={a.slug}
                        className={`pick-card ${archetype?.slug === a.slug ? 'active' : ''}`}
                        onClick={() => setArchetype(a)}
                        type="button"
                      >
                        <div className="pc-title">
                          <PickIcon name={a.icon} size={16} className="violet-accent" />
                          <span>{a.name}</span>
                        </div>
                        <div className="pc-slug">{a.slug}</div>
                        <div className="pc-services">
                          {a.services.map((s) => <span key={s} className="service-tag">{s}</span>)}
                        </div>
                      </button>
                    ))}
                  </div>
                </>
              ) : (
                <>
                  <div className="type-label">
                    Pick individual services. Every selected decky will expose the same set.
                  </div>
                  <div className="pick-grid">
                    {DEFAULT_SERVICES.map((s) => {
                      const on = selectedServices.includes(s.slug);
                      return (
                        <button
                          key={s.slug}
                          className={`pick-card ${on ? 'active' : ''}`}
                          onClick={() => toggleService(s.slug)}
                          type="button"
                        >
                          <div className="pc-title">
                            <PickIcon name={s.icon} size={14} className="violet-accent" />
                            <span>{s.name}</span>
                          </div>
                          <div className="pc-slug">
                            {s.proto.toUpperCase()} · {s.port} · risk={s.risk}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </>
              )}
            </>
          )}

          {step === 1 && (
            <>
              <div className="type-label">How many, and what to call them.</div>
              <div className="grid-2">
                <div className="tweak-group">
                  <label>PREFIX</label>
                  <input
                    className="input"
                    value={prefix}
                    onChange={(e) => setPrefix(e.target.value.replace(/\s+/g, '-'))}
                  />
                </div>
                <div className="tweak-group">
                  <label>COUNT ({count})</label>
                  <input
                    type="range"
                    min={1}
                    max={50}
                    value={count}
                    onChange={(e) => setCount(parseInt(e.target.value, 10))}
                  />
                </div>
              </div>

              {effectiveServices.length > 0 && (
                <div className="tweak-group">
                  <label>PER-SERVICE CONFIG</label>
                  <div className="dim" style={{ fontSize: '0.62rem', letterSpacing: 1, marginBottom: 6 }}>
                    Click a service to set passwords, banners, response codes, TLS
                    material — applied to every decky in this batch via INI
                    subsections.
                  </div>
                  <div className="wizard-svc-list">
                    {effectiveServices.map((svc) => {
                      const open = openSvcCfg === svc;
                      const overrideCount = Object.values(serviceConfigs[svc] ?? {})
                        .filter((v) => v !== '' && v !== undefined && v !== null && v !== false)
                        .length;
                      return (
                        <div key={svc} className="wizard-svc-block">
                          <button
                            type="button"
                            className={`wizard-svc-toggle ${open ? 'open' : ''}`}
                            onClick={() => setOpenSvcCfg(open ? null : svc)}
                          >
                            <span className="wizard-svc-caret">{open ? '▾' : '▸'}</span>
                            <span className="wizard-svc-name">{svc}</span>
                            {overrideCount > 0 && (
                              <span className="wizard-svc-badge">{overrideCount} set</span>
                            )}
                          </button>
                          {open && (
                            <div className="wizard-svc-fields">
                              <ServiceConfigFields
                                serviceSlug={svc}
                                idScope={`wizard-${svc}`}
                                value={serviceConfigs[svc] ?? {}}
                                onChange={(next) =>
                                  setServiceConfigs((s) => ({ ...s, [svc]: next }))}
                                onSchema={(sch) =>
                                  setServiceSchemas((s) => ({ ...s, [svc]: sch.fields }))}
                              />
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              <div className="code-block">
                <span className="comment"># preview: deckies that will come online</span>
                {'\n'}
                {previewLines.join('\n')}
              </div>
            </>
          )}

          {step === 2 && (
            <>
              <div className="type-label">
                Mutation rotates MAC / IP / hostname so attackers can't re-target.
              </div>
              <div
                style={{
                  display: 'flex', gap: 10, alignItems: 'center',
                  padding: 14, border: '1px solid var(--border)',
                }}
              >
                <input
                  id="mut"
                  type="checkbox"
                  checked={mutate}
                  onChange={(e) => setMutate(e.target.checked)}
                  style={{ accentColor: 'var(--matrix)' }}
                />
                <label htmlFor="mut" style={{ fontSize: '0.8rem', letterSpacing: 1 }}>
                  ENABLE PERIODIC MUTATION
                </label>
              </div>
              {mutate && (
                <div className="tweak-group">
                  <label>INTERVAL ({mutateEvery} minutes)</label>
                  <input
                    type="range"
                    min={5}
                    max={240}
                    step={5}
                    value={mutateEvery}
                    onChange={(e) => setMutateEvery(parseInt(e.target.value, 10))}
                  />
                  <div className="dim" style={{ fontSize: '0.65rem', letterSpacing: 1 }}>
                    Next mutation will occur {mutateEvery}m after deploy.
                  </div>
                </div>
              )}
            </>
          )}

          {step === 3 && (
            <>
              <div className="type-label">
                {!deploying
                  ? 'Ready to deploy. This will write to the fleet and start the listener.'
                  : 'Deploying...'}
              </div>
              <div className="code-block" style={{ minHeight: 180 }}>
                {log.length === 0 && !deploying && (
                  <>
                    <span className="comment"># decnet deploy \</span>{'\n'}
                    {pickMode === 'archetype' && archetype && (
                      <>
                        <span className="key">  --archetype</span>{' '}
                        <span className="str">{archetype.slug}</span>{' \\'}{'\n'}
                      </>
                    )}
                    <span className="key">  --count</span>{' '}
                    <span className="str">{count}</span>{' \\'}{'\n'}
                    <span className="key">  --prefix</span>{' '}
                    <span className="str">{prefix}</span>{' \\'}{'\n'}
                    <span className="key">  --mutate</span>{' '}
                    <span className="str">{mutate ? `${mutateEvery}m` : 'off'}</span>
                    {pickMode === 'services' && selectedServices.length > 0 && (
                      <>
                        {' \\'}{'\n'}
                        <span className="key">  --services</span>{' '}
                        <span className="str">{selectedServices.join(',')}</span>
                      </>
                    )}
                  </>
                )}
                {log.map((l, i) => <div key={i}>{l}</div>)}
                {deploying && log.length < 7 && <span className="replay-cursor" />}
              </div>
              {deployErr && (
                <div
                  style={{
                    border: '1px solid var(--alert)',
                    color: 'var(--alert)',
                    padding: '8px 12px',
                    fontSize: '0.75rem',
                    letterSpacing: 1,
                  }}
                >
                  ✖ {deployErr}
                </div>
              )}
            </>
          )}
        </div>

      </>
    </Modal>
  );
};
