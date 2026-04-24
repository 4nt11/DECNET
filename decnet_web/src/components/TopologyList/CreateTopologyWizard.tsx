import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { X, Server, Cpu, FileText, Sparkles, Check } from '../../icons';
import api from '../../utils/api';
import { useEscapeKey } from '../../hooks/useEscapeKey';
import { useFocusTrap } from '../../hooks/useFocusTrap';
import './CreateTopologyWizard.css';

/* Shape of GET /swarm/hosts rows (mirrors SwarmHostView). */
interface SwarmHost {
  uuid: string;
  name: string;
  address: string;
  agent_port: number;
  status: string;
  last_heartbeat: string | null;
}

interface TopologySummary {
  id: string;
  name: string;
  mode: string;
  target_host_uuid: string | null;
  status: string;
  version: number;
  needs_resync?: boolean;
  created_at: string;
  status_changed_at: string | null;
}

type Kind = 'blank' | 'seeded';

interface Props {
  open: boolean;
  onClose: () => void;
  onCreated: (row: TopologySummary) => void;
}

const LOCAL_CARD_ID = '__local__';

const CreateTopologyWizard: React.FC<Props> = ({ open, onClose, onCreated }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEscapeKey(onClose, open);
  useFocusTrap(panelRef, open);

  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, [open]);

  const [step, setStep] = useState<0 | 1>(0);
  const [targetId, setTargetId] = useState<string | null>(null); // LOCAL_CARD_ID or host uuid
  const [kind, setKind] = useState<Kind | null>(null);
  const [name, setName] = useState('');
  const [depth, setDepth] = useState(2);
  const [branchingFactor, setBranchingFactor] = useState(2);
  const [minDeckies, setMinDeckies] = useState(1);
  const [maxDeckies, setMaxDeckies] = useState(3);
  const [seed, setSeed] = useState<string>('');

  const [hosts, setHosts] = useState<SwarmHost[]>([]);
  const [hostsLoaded, setHostsLoaded] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  /* Reset state whenever the modal opens so a cancelled run doesn't
   * leak into the next attempt. */
  useEffect(() => {
    if (!open) return;
    setStep(0);
    setTargetId(null);
    setKind(null);
    setName('');
    setDepth(2);
    setBranchingFactor(2);
    setMinDeckies(1);
    setMaxDeckies(3);
    setSeed('');
    setErr(null);
    setSubmitting(false);
  }, [open]);

  const fetchHosts = useCallback(async () => {
    try {
      const { data } = await api.get<SwarmHost[]>('/swarm/hosts');
      setHosts(data ?? []);
    } catch (e) {
      /* Non-fatal: the user can still pick LOCAL. */
      setHosts([]);
    } finally {
      setHostsLoaded(true);
    }
  }, []);

  useEffect(() => {
    if (open) fetchHosts();
  }, [open, fetchHosts]);

  const selectedHost = useMemo(
    () => (targetId && targetId !== LOCAL_CARD_ID ? hosts.find((h) => h.uuid === targetId) ?? null : null),
    [targetId, hosts],
  );

  const canNext = step === 0 ? !!targetId : !!kind && name.trim().length > 0;

  const handleCreate = async () => {
    if (!targetId || !kind) return;
    setSubmitting(true);
    setErr(null);
    const isAgent = targetId !== LOCAL_CARD_ID;
    const targetHostUuid = isAgent ? targetId : null;
    const mode = isAgent ? 'agent' : 'unihost';
    try {
      if (kind === 'blank') {
        const { data } = await api.post<TopologySummary>('/topologies/blank', {
          name: name.trim(),
          mode,
          target_host_uuid: targetHostUuid,
        });
        onCreated(data);
      } else {
        const body: Record<string, unknown> = {
          name: name.trim(),
          mode,
          target_host_uuid: targetHostUuid,
          depth,
          branching_factor: branchingFactor,
          deckies_per_lan_min: minDeckies,
          deckies_per_lan_max: maxDeckies,
          randomize_services: true,
        };
        const parsedSeed = seed.trim();
        if (parsedSeed !== '') {
          const n = Number(parsedSeed);
          if (Number.isFinite(n) && n >= 0) body.seed = Math.floor(n);
        }
        const { data } = await api.post<TopologySummary>('/topologies/', body);
        onCreated(data);
      }
    } catch (e) {
      const msg =
        // axios response shape
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        ((e as any)?.response?.data?.detail as string | undefined) ??
        (e as Error)?.message ??
        'create failed';
      setErr(msg);
    } finally {
      setSubmitting(false);
    }
  };

  if (!open) return null;

  /* The two cards in step-0 grid: LOCAL first, then each enrolled agent. */
  const step0Cards = (
    <>
      <div
        onClick={() => setTargetId(LOCAL_CARD_ID)}
        className={`ctw-card ${targetId === LOCAL_CARD_ID ? 'selected' : ''}`}
      >
        <div className="ctw-card-head">
          <Cpu size={16} className="ctw-violet" />
          <span className="ctw-card-name">RUN LOCALLY</span>
        </div>
        <div className="ctw-card-sub">master</div>
        <div className="ctw-card-desc">Topology materialises on this master host via the local docker daemon.</div>
      </div>

      {hosts.map((h) => {
        const routable = h.status === 'active' || h.status === 'enrolled';
        return (
          <div
            key={h.uuid}
            onClick={() => routable && setTargetId(h.uuid)}
            className={`ctw-card ${targetId === h.uuid ? 'selected' : ''} ${routable ? '' : 'disabled'}`}
            title={routable ? undefined : `host is ${h.status}`}
          >
            <div className="ctw-card-head">
              <Server size={16} className="ctw-violet" />
              <span className="ctw-card-name">{h.name}</span>
            </div>
            <div className="ctw-card-sub">
              {h.address}:{h.agent_port} · {h.status}
            </div>
            <div className="ctw-card-desc">
              Topology pushed over mTLS to this swarm worker.
              {h.last_heartbeat && (
                <>
                  <br />
                  <span className="ctw-dim">last seen {new Date(h.last_heartbeat).toLocaleTimeString()}</span>
                </>
              )}
            </div>
          </div>
        );
      })}

      {hostsLoaded && hosts.length === 0 && (
        <div className="ctw-card-note">
          No agents enrolled yet. Only local deployment is available.
        </div>
      )}
    </>
  );

  const step1Cards = (
    <>
      <div
        onClick={() => setKind('blank')}
        className={`ctw-card ${kind === 'blank' ? 'selected' : ''}`}
      >
        <div className="ctw-card-head">
          <FileText size={16} className="ctw-violet" />
          <span className="ctw-card-name">BLANK</span>
        </div>
        <div className="ctw-card-sub">start from scratch</div>
        <div className="ctw-card-desc">
          Creates an empty topology with a single DMZ LAN and its gateway decky. Build out the rest in the editor.
        </div>
      </div>
      <div
        onClick={() => setKind('seeded')}
        className={`ctw-card ${kind === 'seeded' ? 'selected' : ''}`}
      >
        <div className="ctw-card-head">
          <Sparkles size={16} className="ctw-violet" />
          <span className="ctw-card-name">SEED-BASED</span>
        </div>
        <div className="ctw-card-sub">procedurally generated</div>
        <div className="ctw-card-desc">
          Runs the MazeNET generator with depth/branching/deckies parameters. Seed is optional — omit for a fresh roll.
        </div>
      </div>
    </>
  );

  const targetLabel =
    targetId === LOCAL_CARD_ID ? 'RUN LOCALLY' : selectedHost ? selectedHost.name : '—';

  return (
    <div className="ctw-backdrop" onClick={onClose}>
      <div className="ctw-modal" ref={panelRef} role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        <div className="ctw-head">
          <h3>
            <Sparkles size={14} style={{ marginRight: 8 }} /> NEW TOPOLOGY
          </h3>
          <button className="ctw-close" onClick={onClose} aria-label="close">
            <X size={16} />
          </button>
        </div>

        <div className="ctw-steps">
          {['TARGET', 'TYPE'].map((label, i) => (
            <div
              key={label}
              className={`ctw-step ${i === step ? 'active' : i < step ? 'done' : ''}`}
            >
              {i + 1}. {label}
              {i < step && <Check size={11} style={{ marginLeft: 6 }} />}
            </div>
          ))}
        </div>

        <div className="ctw-body">
          {step === 0 && (
            <>
              <div className="ctw-label">Where should this topology run?</div>
              <div className="ctw-grid-3">{step0Cards}</div>
              <div className="ctw-note">
                <strong>HEADS UP:</strong> the gateway decky publishes its
                service ports on the target host (e.g. <code>0.0.0.0:22</code>{' '}
                for SSH). Move any host-side daemons off collision ports
                BEFORE deploying — otherwise docker will fail with{' '}
                <code>address already in use</code>. On a fresh VPS this
                usually means relocating sshd to <code>2222</code>.
              </div>
            </>
          )}

          {step === 1 && (
            <>
              <div className="ctw-label">
                Target: <span className="ctw-violet">{targetLabel}</span> · pick a starting point.
              </div>
              <div className="ctw-grid-2">{step1Cards}</div>

              <div className="ctw-field">
                <label>NAME</label>
                <input
                  autoFocus
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. honeynet-dev"
                  maxLength={64}
                />
              </div>

              {kind === 'seeded' && (
                <div className="ctw-grid-2">
                  <div className="ctw-field">
                    <label>DEPTH ({depth})</label>
                    <input type="range" min={1} max={6} value={depth} onChange={(e) => setDepth(+e.target.value)} />
                  </div>
                  <div className="ctw-field">
                    <label>BRANCHING ({branchingFactor})</label>
                    <input
                      type="range"
                      min={1}
                      max={4}
                      value={branchingFactor}
                      onChange={(e) => setBranchingFactor(+e.target.value)}
                    />
                  </div>
                  <div className="ctw-field">
                    <label>DECKIES / LAN MIN ({minDeckies})</label>
                    <input
                      type="range"
                      min={0}
                      max={8}
                      value={minDeckies}
                      onChange={(e) => {
                        const v = +e.target.value;
                        setMinDeckies(v);
                        if (v > maxDeckies) setMaxDeckies(v);
                      }}
                    />
                  </div>
                  <div className="ctw-field">
                    <label>DECKIES / LAN MAX ({maxDeckies})</label>
                    <input
                      type="range"
                      min={Math.max(1, minDeckies)}
                      max={12}
                      value={maxDeckies}
                      onChange={(e) => setMaxDeckies(+e.target.value)}
                    />
                  </div>
                  <div className="ctw-field" style={{ gridColumn: '1 / -1' }}>
                    <label>SEED (optional, integer)</label>
                    <input
                      type="text"
                      value={seed}
                      onChange={(e) => setSeed(e.target.value)}
                      placeholder="leave blank for random"
                    />
                  </div>
                </div>
              )}
            </>
          )}

          {err && <div className="ctw-error">{err}</div>}
        </div>

        <div className="ctw-foot">
          <button className="ctw-btn ghost" onClick={onClose}>
            CANCEL
          </button>
          <div className="ctw-foot-right">
            {step > 0 && !submitting && (
              <button className="ctw-btn ghost" onClick={() => setStep(0)}>
                ← BACK
              </button>
            )}
            {step === 0 && (
              <button className="ctw-btn" disabled={!canNext} onClick={() => setStep(1)}>
                NEXT →
              </button>
            )}
            {step === 1 && (
              <button className="ctw-btn" disabled={!canNext || submitting} onClick={handleCreate}>
                {submitting ? 'CREATING…' : 'CREATE'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default CreateTopologyWizard;
