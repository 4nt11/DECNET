import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Cpu, Database, Globe, Monitor, Network, PlusCircle, PowerOff,
  RefreshCw, Server, Shield, Terminal, Plus, X,
} from '../icons';
import api from '../utils/api';
import { ARCHETYPES as FALLBACK_ARCHETYPES, DEFAULT_SERVICES } from './MazeNET/data';
import { useToast } from './Toasts/useToast';
import Modal from './Modal/Modal';
import { useServiceRegistry } from '../hooks/useServiceRegistry';
import ServiceConfigForm from './ServiceConfigForm';
import ServiceConfigFields, {
  type FormState as SvcFormState,
  type ServiceConfigFieldDTO as SvcFieldDTO,
  compactPayload as svcCompactPayload,
} from './ServiceConfigFields';
import './DeckyFleet.css';

// ─── Types ────────────────────────────────────────────────────────────────

interface SwarmMeta {
  host_uuid: string;
  host_name: string;
  host_address: string;
  host_status: string;
  state: string;
  last_error: string | null;
  last_seen: string | null;
}

interface Decky {
  name: string;
  ip: string;
  services: string[];
  distro: string;
  hostname: string;
  archetype: string | null;
  service_config: Record<string, Record<string, unknown>>;
  mutate_interval: number | null;
  last_mutated: number;
  swarm?: SwarmMeta;
}

interface SwarmDeckyRaw {
  decky_name: string;
  decky_ip: string | null;
  host_uuid: string;
  host_name: string;
  host_address: string;
  host_status: string;
  services: string[];
  state: string;
  last_error: string | null;
  last_seen: string | null;
  hostname: string | null;
  distro: string | null;
  archetype: string | null;
  service_config: Record<string, Record<string, unknown>>;
  mutate_interval: number | null;
  last_mutated: number;
}

interface Archetype {
  slug: string;
  name: string;
  services: string[];
  icon: string;
}

type FilterKey = 'all' | 'active' | 'hot' | 'idle';
type DeckyStatus = 'active' | 'hot' | 'idle';

// ─── Helpers ──────────────────────────────────────────────────────────────

const _archetypeIcon = (slug: string): string => {
  const s = slug.toLowerCase();
  if (s.includes('windows') || s.includes('workstation')) return 'monitor';
  if (s.includes('domain')) return 'shield';
  if (s.includes('database') || s.includes('sql')) return 'database';
  if (s.includes('iot') || s.includes('ot')) return 'cpu';
  if (s.includes('web')) return 'globe';
  return 'server';
};

// Compact icon resolver for lucide names we use in the wizard.
const PickIcon: React.FC<{ name: string; size?: number; className?: string }> = (
  { name, size = 16, className },
) => {
  const map: Record<string, React.ComponentType<{ size?: number; className?: string }>> = {
    server: Server, monitor: Monitor, shield: Shield, database: Database,
    cpu: Cpu, globe: Globe, terminal: Terminal,
  };
  const Cmp = map[name] ?? Server;
  return <Cmp size={size} className={className} />;
};

// Map swarm state -> visual dot status. "active" with no recent hit is idle;
// we don't have per-decky hit counts here, so treat running = active.
const _dotFor = (d: Decky): DeckyStatus => {
  if (!d.swarm) return 'active';
  switch (d.swarm.state) {
    case 'running': return 'active';
    case 'failed':
    case 'teardown_failed': return 'hot';
    case 'pending':
    case 'tearing_down':
    case 'degraded': return 'idle';
    default: return 'idle';
  }
};

// Hits placeholder — backend doesn't expose per-decky 24h hit count yet.
const _hitsFor = (_d: Decky): number => 0;

const _stateColor = (state: string): string => {
  switch (state) {
    case 'running': return 'var(--matrix)';
    case 'degraded':
    case 'tearing_down':
    case 'pending': return 'var(--violet)';
    case 'failed':
    case 'teardown_failed': return 'var(--alert)';
    default: return 'var(--border)';
  }
};

// ─── Decky card ───────────────────────────────────────────────────────────

interface DeckyCardProps {
  decky: Decky;
  mutating: boolean;
  isAdmin: boolean;
  armed: string | null;
  tdBusy: boolean;
  onForce: (name: string) => void;
  onTeardown: (d: Decky) => void;
  onIntervalChange: (name: string, current: number | null) => void;
  onInspect: (d: Decky) => void;
  innerRef?: React.Ref<HTMLDivElement>;
  /** Per-decky-eligible service slugs from useServiceRegistry. */
  availableServices: string[];
  /** Called after a successful live add/remove so the parent can
   * optimistically apply the response's services list. */
  onServicesChanged: (deckyName: string, services: string[]) => void;
}

const DeckyCard: React.FC<DeckyCardProps> = ({
  decky, mutating, isAdmin, armed, tdBusy, onForce, onTeardown, onIntervalChange, onInspect,
  innerRef, availableServices, onServicesChanged,
}) => {
  const dot = _dotFor(decky);
  const hits = _hitsFor(decky);
  const hot = dot === 'hot';
  const dotClass = mutating ? 'mutating' : dot;
  const tdKey = decky.swarm ? `td:${decky.swarm.host_uuid}:${decky.name}` : '';

  // Live service mutation is local-only (admin, non-swarm).  Swarm
  // deckies live on a remote agent — the W3 path runs docker compose
  // locally and won't reach the agent's containers (same gap as the
  // canary planter has for agent-pinned topologies; out of scope here).
  const liveServicesEnabled = isAdmin && !decky.swarm;
  const [addOpen, setAddOpen] = useState(false);
  const [addSlug, setAddSlug] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [opError, setOpError] = useState<string | null>(null);
  const [openCfgSvc, setOpenCfgSvc] = useState<string | null>(null);

  const removeService = async (slug: string) => {
    setOpError(null);
    setBusy(slug);
    try {
      const { data } = await api.delete<{ services: string[] }>(
        `/deckies/${encodeURIComponent(decky.name)}/services/${encodeURIComponent(slug)}`,
      );
      onServicesChanged(decky.name, data.services);
    } catch (err) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
        ?? 'Remove failed.';
      setOpError(msg);
    } finally {
      setBusy(null);
    }
  };

  const addService = async () => {
    if (!addSlug) return;
    setOpError(null);
    setBusy(addSlug);
    try {
      const { data } = await api.post<{ services: string[] }>(
        `/deckies/${encodeURIComponent(decky.name)}/services`,
        { name: addSlug },
      );
      onServicesChanged(decky.name, data.services);
      setAddOpen(false);
      setAddSlug('');
    } catch (err) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
        ?? 'Add failed.';
      setOpError(msg);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div
      ref={innerRef}
      className={`decky-card ${hot ? 'hot' : ''}`}
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('button, a, input')) return;
        onInspect(decky);
      }}
      style={{ cursor: 'pointer' }}
    >
      <div className="decky-head">
        <div className="decky-name">
          <span className={`status-dot ${dotClass}`} />
          {decky.name}
        </div>
        <span className="decky-ip">{decky.ip}</span>
      </div>

      {decky.swarm && (
        <div className="decky-swarm-row">
          <span className="decky-swarm-chip">
            <Network size={10} className="dim" />
            <span className="dim">{decky.swarm.host_name}</span>
            <span style={{ opacity: 0.5 }}>@ {decky.swarm.host_address || '—'}</span>
          </span>
          <span
            className="decky-swarm-state"
            style={{
              borderColor: _stateColor(decky.swarm.state),
              color: _stateColor(decky.swarm.state),
            }}
          >
            {decky.swarm.state.toUpperCase()}
          </span>
          {decky.swarm.last_error && (
            <span className="alert-text" title={decky.swarm.last_error} style={{ fontSize: '0.65rem' }}>
              ⚠ {decky.swarm.last_error.slice(0, 48)}
              {decky.swarm.last_error.length > 48 ? '…' : ''}
            </span>
          )}
        </div>
      )}

      <div className="decky-meta">
        <div className="row"><span className="label">HOST</span><span>{decky.hostname}</span></div>
        <div className="row"><span className="label">DISTRO</span><span className="dim">{decky.distro}</span></div>
        <div className="row">
          <span className="label">ARCHETYPE</span>
          <span className="violet-accent">{decky.archetype || '—'}</span>
        </div>
        <div className="row">
          <span className="label">MUTATE</span>
          {!decky.swarm && isAdmin ? (
            <span
              className={decky.mutate_interval ? 'violet-accent' : 'dim'}
              style={{ cursor: 'pointer', textDecoration: 'underline' }}
              onClick={() => onIntervalChange(decky.name, decky.mutate_interval)}
            >
              {decky.mutate_interval ? `EVERY ${decky.mutate_interval}m` : 'DISABLED'}
            </span>
          ) : (
            <span className={decky.mutate_interval ? 'violet-accent' : 'dim'}>
              {decky.mutate_interval ? `EVERY ${decky.mutate_interval}m` : 'DISABLED'}
            </span>
          )}
        </div>
      </div>

      <div>
        <div className="type-label" style={{ marginBottom: 6 }}>EXPOSED</div>
        <div className="decky-services">
          {decky.services.map((s) => (
            <span key={s} className="service-tag" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              {liveServicesEnabled ? (
                <button
                  type="button"
                  className="svc-cfg-toggle-btn"
                  title={`Configure ${s}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setOpenCfgSvc((cur) => (cur === s ? null : s));
                  }}
                >
                  {s}
                </button>
              ) : (
                <span>{s}</span>
              )}
              {liveServicesEnabled && (
                <button
                  type="button"
                  title={`Remove ${s}`}
                  disabled={busy === s}
                  onClick={(e) => { e.stopPropagation(); removeService(s); }}
                  style={{
                    background: 'transparent', border: 'none', padding: 0,
                    color: 'inherit', cursor: busy === s ? 'wait' : 'pointer',
                    opacity: busy === s ? 0.4 : 0.7, lineHeight: 1,
                  }}
                >
                  <X size={9} />
                </button>
              )}
            </span>
          ))}
          {liveServicesEnabled && !addOpen && (
            <button
              type="button"
              className="service-tag"
              onClick={(e) => { e.stopPropagation(); setAddOpen(true); setAddSlug(''); }}
              style={{ cursor: 'pointer', borderStyle: 'dashed' }}
              title="Add service (live)"
            >
              <Plus size={10} /> ADD
            </button>
          )}
        </div>
        {liveServicesEnabled && addOpen && (
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ display: 'flex', gap: 6, marginTop: 6, alignItems: 'center' }}
          >
            <select
              value={addSlug}
              onChange={(e) => setAddSlug(e.target.value)}
              style={{
                flex: 1, fontSize: '0.75rem', padding: '4px 6px',
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid var(--border-color, #30363d)',
                color: 'var(--text-color)',
              }}
            >
              <option value="">— pick a service —</option>
              {availableServices
                .filter((s) => !decky.services.includes(s))
                .map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <button
              type="button"
              disabled={!addSlug || busy === addSlug}
              onClick={addService}
              className="btn violet small"
            >
              {busy === addSlug ? 'ADDING' : 'ADD'}
            </button>
            <button
              type="button"
              onClick={() => { setAddOpen(false); setAddSlug(''); }}
              className="btn small"
            >
              CANCEL
            </button>
          </div>
        )}
        {opError && (
          <div className="alert-text" style={{ fontSize: '0.7rem', marginTop: 6 }}>{opError}</div>
        )}
        {liveServicesEnabled && openCfgSvc && decky.services.includes(openCfgSvc) && (
          <div onClick={(e) => e.stopPropagation()}>
            <ServiceConfigForm
              key={`${decky.name}:${openCfgSvc}`}
              deckyName={decky.name}
              serviceSlug={openCfgSvc}
              currentConfig={decky.service_config?.[openCfgSvc] ?? {}}
            />
          </div>
        )}
      </div>

      <div className="decky-footer">
        <span className="decky-hits">
          <span className="dim">HITS 24h: </span>
          <span
            className={hot ? 'alert-text' : 'matrix-text'}
            style={{ fontWeight: 700 }}
          >
            {hits}
          </span>
        </span>
        <div style={{ display: 'flex', gap: 6 }}>
          {!decky.swarm && isAdmin && (
            <button
              className="btn violet small"
              disabled={mutating}
              onClick={() => onForce(decky.name)}
              title="Force a mutation now"
            >
              <RefreshCw size={10} className={mutating ? 'fx-spin' : ''} />
              {mutating ? 'MUTATING' : 'FORCE MUTATE'}
            </button>
          )}
          {decky.swarm && isAdmin && (
            <button
              className="btn alert small"
              disabled={tdBusy}
              onClick={() => onTeardown(decky)}
              title="Stop this decky on its host"
            >
              <PowerOff size={10} />
              {tdBusy
                ? 'TEARING DOWN…'
                : armed === tdKey ? 'CONFIRM' : 'TEARDOWN'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

// ─── Deploy wizard ────────────────────────────────────────────────────────

interface DeployWizardProps {
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
const _b64encodeUtf8 = (s: string): string => {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
};

const _buildIni = (
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
        serialised = `b64:${_b64encodeUtf8(v)}`;
      } else {
        serialised = typeof v === 'string' ? v : String(v);
      }
      lines.push(`${k}=${serialised}`);
    }
    lines.push('');
  }
  return lines.join('\n');
};

const DeployWizard: React.FC<DeployWizardProps> = ({
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
    const ini = _buildIni(
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

// ─── Interval editor modal ───────────────────────────────────────────────

interface IntervalEditorProps {
  open: boolean;
  deckyName: string;
  current: number | null;
  onClose: () => void;
  onSave: (minutes: number | null) => void;
}

const IntervalEditor: React.FC<IntervalEditorProps> = ({ open, deckyName, current, onClose, onSave }) => {
  const [enabled, setEnabled] = useState<boolean>(current !== null);
  const [minutes, setMinutes] = useState<number>(current ?? 30);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={`MUTATION INTERVAL · ${deckyName}`}
      icon={RefreshCw}
      accent="violet"
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>CANCEL</button>
          <button className="btn violet" onClick={() => onSave(enabled ? minutes : null)}>SAVE</button>
        </>
      }
    >
      <div className="modal-body">
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', padding: 14, border: '1px solid var(--border)' }}>
          <input
            id="interval-enable"
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            style={{ accentColor: 'var(--matrix)' }}
          />
          <label htmlFor="interval-enable" style={{ fontSize: '0.8rem', letterSpacing: 1 }}>
            ENABLE PERIODIC MUTATION
          </label>
        </div>
        {enabled && (
          <div className="tweak-group">
            <label>INTERVAL ({minutes} minutes)</label>
            <input
              type="range"
              min={5}
              max={240}
              step={5}
              value={minutes}
              onChange={(e) => setMinutes(parseInt(e.target.value, 10))}
            />
            <div className="dim" style={{ fontSize: '0.65rem', letterSpacing: 1 }}>
              Applied on the next mutation cycle.
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
};

// ─── Fleet page ──────────────────────────────────────────────────────────

interface FleetProps {
  searchQuery?: string;
}

const DeckyFleet: React.FC<FleetProps> = ({ searchQuery = '' }) => {
  const { push } = useToast();
  const serviceRegistry = useServiceRegistry();
  const [deckies, setDeckies] = useState<Decky[]>([]);
  const [loading, setLoading] = useState(true);
  const [mutating, setMutating] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [deployMode, setDeployMode] = useState<{ mode: string; swarm_host_count: number } | null>(null);
  const [filter, setFilter] = useState<FilterKey>('all');
  const [showDeploy, setShowDeploy] = useState(false);
  const [armed, setArmed] = useState<string | null>(null);
  const [tearingDown, setTearingDown] = useState<Set<string>>(new Set());
  const [archetypes, setArchetypes] = useState<Archetype[]>(FALLBACK_ARCHETYPES);
  const [localSearch, setLocalSearch] = useState<string>('');
  const [intervalEditor, setIntervalEditor] = useState<{ name: string; current: number | null } | null>(null);
  const cardRefs = useRef<Map<string, HTMLDivElement>>(new Map());

  const lastSearchPropRef = useRef<string>(searchQuery);
  if (lastSearchPropRef.current !== searchQuery) {
    lastSearchPropRef.current = searchQuery;
    // Mirror the topbar search into local state; filter-decky events can
    // override it in-session.
    if (localSearch !== searchQuery) setLocalSearch(searchQuery);
  }

  const arm = (key: string) => {
    setArmed(key);
    window.setTimeout(() => setArmed((p) => (p === key ? null : p)), 4000);
  };

  const fetchDeckies = async (mode?: string) => {
    try {
      if (mode === 'swarm') {
        const res = await api.get<SwarmDeckyRaw[]>('/swarm/deckies');
        const normalized: Decky[] = res.data.map((s) => ({
          name: s.decky_name,
          ip: s.decky_ip || '—',
          services: s.services || [],
          distro: s.distro || 'unknown',
          hostname: s.hostname || '—',
          archetype: s.archetype,
          service_config: s.service_config || {},
          mutate_interval: s.mutate_interval,
          last_mutated: s.last_mutated || 0,
          swarm: {
            host_uuid: s.host_uuid,
            host_name: s.host_name,
            host_address: s.host_address,
            host_status: s.host_status,
            state: s.state,
            last_error: s.last_error,
            last_seen: s.last_seen,
          },
        }));
        setDeckies(normalized);
      } else {
        const res = await api.get<Decky[]>('/deckies');
        setDeckies(res.data);
      }
    } catch (err) {
      console.error('Failed to fetch decky fleet', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchRole = async () => {
    try {
      const res = await api.get('/config');
      setIsAdmin(res.data.role === 'admin');
    } catch {
      setIsAdmin(false);
    }
  };

  const fetchDeployMode = async () => {
    try {
      const res = await api.get('/system/deployment-mode');
      setDeployMode({ mode: res.data.mode, swarm_host_count: res.data.swarm_host_count });
      return res.data.mode as string;
    } catch {
      setDeployMode(null);
      return undefined;
    }
  };

  const fetchArchetypes = async () => {
    try {
      const res = await api.get<{ archetypes: { slug: string; display_name: string; services: string[] }[] }>(
        '/topologies/archetypes',
      );
      const list: Archetype[] = res.data.archetypes.map((a) => ({
        slug: a.slug,
        name: a.display_name,
        services: a.services,
        icon: _archetypeIcon(a.slug),
      }));
      if (list.length) setArchetypes(list);
    } catch {
      // fall back to bundled list
    }
  };

  const handleMutate = async (name: string): Promise<boolean> => {
    setMutating(name);
    try {
      await api.post(`/deckies/${name}/mutate`, {}, { timeout: 120000 });
      await fetchDeckies(deployMode?.mode);
      push({ text: `MUTATED · ${name.toUpperCase()}`, tone: 'matrix', icon: 'refresh-cw' });
      return true;
    } catch (err: unknown) {
      console.error('Failed to mutate', err);
      const e = err as { code?: string };
      const msg = e.code === 'ECONNABORTED'
        ? `MUTATION TIMED OUT · ${name.toUpperCase()}`
        : `MUTATION FAILED · ${name.toUpperCase()}`;
      push({ text: msg, tone: 'alert', icon: 'alert-triangle' });
      return false;
    } finally {
      setMutating(null);
    }
  };

  const handleMutateAll = async () => {
    if (!isAdmin) {
      push({ text: 'ADMIN REQUIRED', tone: 'alert', icon: 'alert-triangle' });
      return;
    }
    const targets = deckies.filter(d => !d.swarm || d.swarm.state === 'running');
    if (targets.length === 0) {
      push({ text: 'NO DECKIES TO MUTATE', tone: 'violet', icon: 'info' });
      return;
    }
    push({ text: `MUTATING FLEET · ${targets.length} DECKIES`, tone: 'violet', icon: 'refresh-cw' });
    let failed = 0;
    for (const d of targets) {
      const ok = await handleMutate(d.name);
      if (!ok) failed++;
    }
    if (failed === 0) {
      push({ text: 'FLEET MUTATED', tone: 'matrix', icon: 'check-circle' });
    } else {
      push({ text: `FLEET MUTATED · ${failed} FAILED`, tone: 'alert', icon: 'alert-triangle' });
    }
  };

  const handleIntervalChange = (name: string, current: number | null) => {
    setIntervalEditor({ name, current });
  };

  const handleIntervalSave = async (minutes: number | null) => {
    if (!intervalEditor) return;
    const { name } = intervalEditor;
    try {
      await api.put(`/deckies/${name}/mutate-interval`, { mutate_interval: minutes });
      setIntervalEditor(null);
      fetchDeckies(deployMode?.mode);
      push({
        text: minutes === null
          ? `INTERVAL · ${name.toUpperCase()} · DISABLED`
          : `INTERVAL · ${name.toUpperCase()} · ${minutes}m`,
        tone: 'matrix',
        icon: 'refresh-cw',
      });
    } catch (err) {
      console.error('Failed to update interval', err);
      push({ text: `INTERVAL UPDATE FAILED · ${name.toUpperCase()}`, tone: 'alert', icon: 'alert-triangle' });
    }
  };

  const handleTeardown = async (d: Decky) => {
    if (!d.swarm) return;
    const key = `td:${d.swarm.host_uuid}:${d.name}`;
    if (armed !== key) { arm(key); return; }
    setArmed(null);
    setTearingDown((prev) => new Set(prev).add(d.name));
    try {
      await api.post(`/swarm/hosts/${d.swarm.host_uuid}/teardown`, { decky_id: d.name });
      await fetchDeckies(deployMode?.mode);
      push({ text: `TORN DOWN · ${d.name.toUpperCase()}`, tone: 'matrix', icon: 'check-circle' });
    } catch (err: unknown) {
      const e = err as { response?: { data?: { detail?: string } } };
      push({
        text: `TEARDOWN FAILED · ${e?.response?.data?.detail || d.name}`,
        tone: 'alert',
        icon: 'alert-triangle',
      });
    } finally {
      setTearingDown((prev) => {
        const next = new Set(prev);
        next.delete(d.name);
        return next;
      });
    }
  };

  const handleInspect = (d: Decky) => {
    window.dispatchEvent(new CustomEvent('decnet:cmd', {
      detail: { id: 'filter-decky', payload: d.name },
    }));
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const mode = await fetchDeployMode();
      if (cancelled) return;
      await Promise.all([fetchDeckies(mode), fetchRole(), fetchArchetypes()]);
    })();
    const interval = window.setInterval(() => {
      fetchDeployMode().then((m) => fetchDeckies(m));
    }, 10000);
    return () => { cancelled = true; window.clearInterval(interval); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Phase-2 decnet:cmd bus: deploy, mutate-all, filter-decky
  useEffect(() => {
    const onCmd = (e: Event) => {
      const detail = (e as CustomEvent).detail as { id?: string; payload?: string };
      if (!detail?.id) return;
      if (detail.id === 'deploy') {
        setShowDeploy(true);
        return;
      }
      if (detail.id === 'mutate-all') {
        void handleMutateAll();
        return;
      }
      if (detail.id === 'filter-decky' && typeof detail.payload === 'string') {
        const name = detail.payload;
        setLocalSearch(name);
        push({ text: `FILTERING · ${name.toUpperCase()}`, tone: 'violet', icon: 'crosshair' });
        // Defer so React renders filtered grid first.
        window.setTimeout(() => {
          const el = cardRefs.current.get(name);
          if (el) el.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }, 80);
      }
    };
    window.addEventListener('decnet:cmd', onCmd);
    return () => window.removeEventListener('decnet:cmd', onCmd);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deckies, isAdmin]);

  const counts = useMemo(() => {
    const c = { all: deckies.length, active: 0, hot: 0, idle: 0 } as Record<FilterKey, number>;
    for (const d of deckies) {
      const s = _dotFor(d);
      c[s] += 1;
    }
    return c;
  }, [deckies]);

  const visible = useMemo(() => {
    const base = filter === 'all' ? deckies : deckies.filter((d) => _dotFor(d) === filter);
    const q = localSearch.trim().toLowerCase();
    if (!q) return base;
    return base.filter((d) =>
      d.name.toLowerCase().includes(q)
      || (d.ip || '').toLowerCase().includes(q)
      || (d.hostname || '').toLowerCase().includes(q),
    );
  }, [deckies, filter, localSearch]);
  const isSwarm = deployMode?.mode === 'swarm';

  if (loading) {
    return (
      <div className="fleet-root">
        <div className="dim" style={{ padding: '40px', textAlign: 'center', letterSpacing: 2 }}>
          SCANNING NETWORK FOR DECOYS...
        </div>
      </div>
    );
  }

  return (
    <div className="fleet-root">
      <div className="page-header">
        <div className="page-title-group">
          <h1>DECOY FLEET</h1>
          <span className="page-sub">
            {deckies.length} DECKIES DEPLOYED · {counts.active + counts.hot} ACTIVE · {counts.hot} UNDER SIEGE
            {deployMode && (
              <> · [{isSwarm ? `SWARM × ${deployMode.swarm_host_count}` : 'UNIHOST'}]</>
            )}
          </span>
        </div>
        <div className="actions">
          <div className="fleet-filter-group">
            {([['all', 'ALL'], ['active', 'ACTIVE'], ['hot', 'HOT'], ['idle', 'IDLE']] as [FilterKey, string][]).map(
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
          {isAdmin && (
            <button className="btn violet" onClick={() => setShowDeploy(true)}>
              <PlusCircle size={12} /> DEPLOY DECKIES
            </button>
          )}
        </div>
      </div>

      <div className="grid-fleet">
        {visible.length === 0 ? (
          <div className="fleet-empty">
            <Server size={32} className="dim" />
            <span className="dim">
              {deckies.length === 0
                ? 'NO DECOYS DEPLOYED IN THIS SECTOR'
                : 'NO DECOYS MATCH CURRENT FILTER'}
            </span>
            {isAdmin && deckies.length === 0 && (
              <button className="btn violet" onClick={() => setShowDeploy(true)}>
                <PlusCircle size={12} /> DEPLOY DECKIES
              </button>
            )}
          </div>
        ) : (
          visible.map((d) => (
            <DeckyCard
              key={d.name}
              decky={d}
              mutating={mutating === d.name}
              isAdmin={isAdmin}
              armed={armed}
              tdBusy={tearingDown.has(d.name) || d.swarm?.state === 'tearing_down'}
              onForce={(name) => { void handleMutate(name); }}
              onTeardown={handleTeardown}
              onIntervalChange={handleIntervalChange}
              onInspect={handleInspect}
              innerRef={(el: HTMLDivElement | null) => {
                if (el) cardRefs.current.set(d.name, el);
                else cardRefs.current.delete(d.name);
              }}
              availableServices={serviceRegistry.perDecky}
              onServicesChanged={(name, services) => {
                setDeckies((prev) => prev.map((row) =>
                  row.name === name ? { ...row, services } : row,
                ));
              }}
            />
          ))
        )}
      </div>

      <DeployWizard
        open={showDeploy}
        archetypes={archetypes}
        fleetSize={deckies.length}
        onClose={() => setShowDeploy(false)}
        onComplete={(count) => {
          setShowDeploy(false);
          fetchDeckies(deployMode?.mode);
          push({
            text: `DEPLOYED · ${count} DECK${count === 1 ? 'Y' : 'IES'}`,
            tone: 'matrix',
            icon: 'check-circle',
          });
        }}
      />

      <IntervalEditor
        key={intervalEditor?.name ?? 'closed'}
        open={intervalEditor !== null}
        deckyName={intervalEditor?.name ?? ''}
        current={intervalEditor?.current ?? null}
        onClose={() => setIntervalEditor(null)}
        onSave={handleIntervalSave}
      />
    </div>
  );
};

export default DeckyFleet;
