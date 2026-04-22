import React, { useEffect, useRef, useState } from 'react';
import api from '../utils/api';
import EmptyState from './EmptyState/EmptyState';
import Modal from './Modal/Modal';
import './Dashboard.css';
import './Swarm.css';
import './DeckyFleet.css';
import {
  AlertTriangle, Check, Copy, HardDrive, PowerOff, RefreshCw, RotateCcw,
  Server, Trash2, UserPlus, Wifi, WifiOff,
} from 'lucide-react';

interface SwarmHost {
  uuid: string;
  name: string;
  address: string;
  agent_port: number;
  status: string;
  last_heartbeat: string | null;
  client_cert_fingerprint: string;
  updater_cert_fingerprint: string | null;
  enrolled_at: string;
  notes: string | null;
}

interface BundleResult {
  token: string;
  host_uuid: string;
  command: string;
  expires_at: string;
}

const shortFp = (fp: string): string => (fp ? fp.slice(0, 16) + '…' : '—');

// ─── Enrollment wizard ────────────────────────────────────────────────────

interface EnrollmentWizardProps {
  open: boolean;
  onClose: () => void;
  onEnrolled: () => void;
}

const EnrollmentWizard: React.FC<EnrollmentWizardProps> = ({ open, onClose, onEnrolled }) => {
  const [step, setStep] = useState(0);
  const [masterHost, setMasterHost] = useState(window.location.hostname);
  const [agentName, setAgentName] = useState('');
  const [withUpdater, setWithUpdater] = useState(true);
  const [useIpvlan, setUseIpvlan] = useState(false);
  const [servicesIni, setServicesIni] = useState<string | null>(null);
  const [servicesIniName, setServicesIniName] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<BundleResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [now, setNow] = useState<number>(Date.now());
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setStep(0);
    setMasterHost(window.location.hostname);
    setAgentName('');
    setWithUpdater(true);
    setUseIpvlan(false);
    setServicesIni(null);
    setServicesIniName(null);
    setSubmitting(false);
    setError(null);
    setResult(null);
    setCopied(false);
    if (fileRef.current) fileRef.current.value = '';
  }, [open]);

  useEffect(() => {
    if (!result) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [result]);

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) {
      setServicesIni(null);
      setServicesIniName(null);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setServicesIni(String(reader.result));
      setServicesIniName(f.name);
    };
    reader.readAsText(f);
  };

  const nameOk = /^[a-z0-9][a-z0-9-]{0,62}$/.test(agentName);

  const generate = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const res = await api.post('/swarm/enroll-bundle', {
        master_host: masterHost,
        agent_name: agentName,
        with_updater: withUpdater,
        use_ipvlan: useIpvlan,
        services_ini: servicesIni,
      });
      setResult(res.data);
      onEnrolled();
    } catch (err: unknown) {
      const e = err as { response?: { data?: { detail?: string } } };
      setError(e?.response?.data?.detail || 'Enrollment bundle creation failed');
    } finally {
      setSubmitting(false);
    }
  };

  const copyCmd = async () => {
    if (!result) return;
    await navigator.clipboard.writeText(result.command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const remainingSecs = result
    ? Math.max(0, Math.floor((new Date(result.expires_at).getTime() - now) / 1000))
    : 0;
  const mm = Math.floor(remainingSecs / 60).toString().padStart(2, '0');
  const ss = (remainingSecs % 60).toString().padStart(2, '0');

  const canNext = step === 0 ? (nameOk && !!masterHost) : true;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="ENROLL SWARM HOST"
      icon={UserPlus}
      accent="violet"
      width="wide"
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>
            {result ? 'CLOSE' : 'CANCEL'}
          </button>
          <div style={{ display: 'flex', gap: 8 }}>
            {step > 0 && !result && (
              <button className="btn ghost" onClick={() => setStep((s) => s - 1)}>← BACK</button>
            )}
            {step < 2 && (
              <button className="btn" disabled={!canNext} onClick={() => setStep((s) => s + 1)}>
                NEXT →
              </button>
            )}
            {step === 2 && !result && (
              <button
                className="btn violet"
                disabled={submitting || !nameOk || !masterHost}
                onClick={generate}
              >
                {submitting ? 'GENERATING…' : 'GENERATE BUNDLE'}
              </button>
            )}
            {result && (
              <button
                className="btn"
                onClick={() => {
                  setResult(null);
                  setAgentName('');
                  setStep(0);
                }}
              >
                <RotateCcw size={12} /> NEW BUNDLE
              </button>
            )}
          </div>
        </>
      }
    >
      <>
        <div className="wizard-steps">
          {['IDENTITY', 'OPTIONS', 'BUNDLE'].map((l, i) => (
            <div key={l} className={`wizard-step ${i === step ? 'active' : i < step ? 'done' : ''}`}>
              {i + 1}. {l}
            </div>
          ))}
        </div>

        <div className="modal-body">
          {step === 0 && (
            <>
              <div className="type-label">Who is this worker, and how does it reach the master?</div>
              <div className="tweak-group">
                <label>MASTER HOST (IP or DNS this agent can reach)</label>
                <input
                  className="input"
                  type="text"
                  value={masterHost}
                  onChange={(e) => setMasterHost(e.target.value)}
                />
              </div>
              <div className="tweak-group">
                <label>AGENT NAME (lowercase, digits, dashes)</label>
                <input
                  className="input"
                  type="text"
                  value={agentName}
                  onChange={(e) => setAgentName(e.target.value.toLowerCase())}
                  pattern="^[a-z0-9][a-z0-9-]{0,62}$"
                  data-autofocus
                />
                {agentName && !nameOk && (
                  <small className="field-warn">
                    <AlertTriangle size={12} /> must match ^[a-z0-9][a-z0-9-]{'{0,62}'}$
                  </small>
                )}
              </div>
            </>
          )}

          {step === 1 && (
            <>
              <div className="type-label">Bundle options — tune for the target environment.</div>
              <div
                style={{
                  display: 'flex', gap: 10, alignItems: 'flex-start',
                  padding: 14, border: '1px solid var(--border)',
                }}
              >
                <input
                  id="with-updater"
                  type="checkbox"
                  checked={withUpdater}
                  onChange={(e) => setWithUpdater(e.target.checked)}
                  style={{ accentColor: 'var(--matrix)', marginTop: 2 }}
                />
                <label htmlFor="with-updater" style={{ fontSize: '0.8rem', letterSpacing: 1, flex: 1 }}>
                  INSTALL UPDATER DAEMON
                  <div className="dim" style={{ fontSize: '0.65rem', letterSpacing: 1, marginTop: 4 }}>
                    Lets the master push code updates to this agent.
                  </div>
                </label>
              </div>
              <div
                style={{
                  display: 'flex', gap: 10, alignItems: 'flex-start',
                  padding: 14, border: '1px solid var(--border)',
                }}
              >
                <input
                  id="use-ipvlan"
                  type="checkbox"
                  checked={useIpvlan}
                  onChange={(e) => setUseIpvlan(e.target.checked)}
                  style={{ accentColor: 'var(--matrix)', marginTop: 2 }}
                />
                <label htmlFor="use-ipvlan" style={{ fontSize: '0.8rem', letterSpacing: 1, flex: 1 }}>
                  USE IPVLAN INSTEAD OF MACVLAN
                  <div className="dim" style={{ fontSize: '0.65rem', letterSpacing: 1, marginTop: 4 }}>
                    Required for VirtualBox/VMware guests bridged over Wi-Fi — Wi-Fi APs bind
                    one MAC per station, so MACVLAN rotates the VM's lease.
                  </div>
                </label>
              </div>
              <div className="tweak-group">
                <label>SERVICES INI (optional)</label>
                <input ref={fileRef} type="file" accept=".ini,.conf,.txt" onChange={handleFile} />
                {servicesIniName && (
                  <div className="dim" style={{ fontSize: '0.65rem', letterSpacing: 1 }}>
                    loaded: {servicesIniName}
                  </div>
                )}
              </div>
            </>
          )}

          {step === 2 && (
            <>
              {!result ? (
                <>
                  <div className="type-label">
                    Review and generate a one-shot bootstrap URL valid for 5 minutes.
                  </div>
                  <div className="code-block">
                    <span className="comment"># enrollment bundle preview</span>{'\n'}
                    <span className="key">  master_host</span>{'  '}<span className="str">{masterHost}</span>{'\n'}
                    <span className="key">  agent_name </span>{'  '}<span className="str">{agentName}</span>{'\n'}
                    <span className="key">  updater    </span>{'  '}<span className="str">{withUpdater ? 'yes' : 'no'}</span>{'\n'}
                    <span className="key">  ipvlan     </span>{'  '}<span className="str">{useIpvlan ? 'yes' : 'no'}</span>{'\n'}
                    <span className="key">  services   </span>{'  '}<span className="str">{servicesIniName ?? '—'}</span>
                  </div>
                  {error && (
                    <div
                      style={{
                        border: '1px solid var(--alert)', color: 'var(--alert)',
                        padding: '8px 12px', fontSize: '0.75rem', letterSpacing: 1,
                      }}
                    >
                      ✖ {error}
                    </div>
                  )}
                </>
              ) : (
                <>
                  <div className="type-label">Paste this on the new worker (as root):</div>
                  <div className="code-block" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {result.command}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn" onClick={copyCmd}>
                      {copied ? <><Check size={12} /> COPIED</> : <><Copy size={12} /> COPY</>}
                    </button>
                  </div>
                  <div className="dim" style={{ fontSize: '0.7rem', letterSpacing: 1 }}>
                    Expires in <strong>{mm}:{ss}</strong> — one-shot, single download.
                    Host UUID: <code>{result.host_uuid}</code>
                  </div>
                  {remainingSecs === 0 && (
                    <div
                      style={{
                        border: '1px solid var(--alert)', color: 'var(--alert)',
                        padding: '8px 12px', fontSize: '0.75rem', letterSpacing: 1,
                        display: 'flex', alignItems: 'center', gap: 8,
                      }}
                    >
                      <AlertTriangle size={14} /> This bundle has expired. Generate another.
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </div>
      </>
    </Modal>
  );
};

// ─── Swarm hosts page ─────────────────────────────────────────────────────

const SwarmHosts: React.FC = () => {
  const [hosts, setHosts] = useState<SwarmHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [decommissioning, setDecommissioning] = useState<Set<string>>(new Set());
  const [tearingDown, setTearingDown] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [showEnroll, setShowEnroll] = useState(false);
  // Two-click arm/commit replaces window.confirm(). Browsers silently
  // suppress confirm() after the "prevent additional dialogs" opt-out,
  // which manifests as a dead button — no network request, no console
  // error. Key format: "<action>:<uuid>".
  const [armed, setArmed] = useState<string | null>(null);
  const arm = (key: string) => {
    setArmed(key);
    setTimeout(() => setArmed((prev) => (prev === key ? null : prev)), 4000);
  };

  const fetchHosts = async () => {
    try {
      const res = await api.get('/swarm/hosts');
      setHosts(res.data);
      setError(null);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to fetch swarm hosts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHosts();
    const t = setInterval(fetchHosts, 10000);
    return () => clearInterval(t);
  }, []);

  const addTo = (set: Set<string>, id: string) => { const n = new Set(set); n.add(id); return n; };
  const removeFrom = (set: Set<string>, id: string) => { const n = new Set(set); n.delete(id); return n; };

  const handleTeardownAll = async (host: SwarmHost) => {
    const key = `teardown:${host.uuid}`;
    if (armed !== key) { arm(key); return; }
    setArmed(null);
    setTearingDown((s) => addTo(s, host.uuid));
    try {
      // 202 Accepted — teardown runs async on the backend.
      await api.post(`/swarm/hosts/${host.uuid}/teardown`, {});
      await fetchHosts();
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Teardown failed');
    } finally {
      setTearingDown((s) => removeFrom(s, host.uuid));
    }
  };

  const handleDecommission = async (host: SwarmHost) => {
    const key = `decom:${host.uuid}`;
    if (armed !== key) { arm(key); return; }
    setArmed(null);
    setDecommissioning((s) => addTo(s, host.uuid));
    try {
      await api.delete(`/swarm/hosts/${host.uuid}`);
      await fetchHosts();
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Decommission failed');
    } finally {
      setDecommissioning((s) => removeFrom(s, host.uuid));
    }
  };

  const online = hosts.filter((h) => h.status === 'online').length;

  return (
    <div className="dashboard swarm-root">
      <div className="page-header">
        <div className="page-title-group">
          <h1><HardDrive size={18} /> SWARM HOSTS</h1>
          <span className="page-sub">
            {loading ? 'LOADING…' : `${hosts.length} ENROLLED · ${online} ONLINE`}
          </span>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={fetchHosts} className="control-btn" disabled={loading}>
            <RefreshCw size={14} /> REFRESH
          </button>
          <button onClick={() => setShowEnroll(true)} className="control-btn primary">
            <UserPlus size={14} /> ENROLL HOST
          </button>
        </div>
      </div>

      {error && <div className="error-box">{error}</div>}

      <div className="panel">
        {loading ? (
          <p>Loading hosts…</p>
        ) : hosts.length === 0 ? (
          <EmptyState
            icon={Server}
            title="NO SWARM HOSTS ENROLLED"
            hint="onboard an agent to expand the fleet"
            cta={{ label: 'ENROLL HOST', onClick: () => setShowEnroll(true) }}
          />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Name</th>
                <th>Address</th>
                <th>Last heartbeat</th>
                <th>Client cert</th>
                <th>Enrolled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h) => (
                <tr key={h.uuid}>
                  <td>
                    {h.status === 'active' ? <Wifi size={16} /> : <WifiOff size={16} />} {h.status}
                  </td>
                  <td>{h.name}</td>
                  <td>{h.address ? `${h.address}:${h.agent_port}` : <em>pending first connect</em>}</td>
                  <td>{h.last_heartbeat ? new Date(h.last_heartbeat).toLocaleString() : '—'}</td>
                  <td title={h.client_cert_fingerprint}><code>{shortFp(h.client_cert_fingerprint)}</code></td>
                  <td>{new Date(h.enrolled_at).toLocaleString()}</td>
                  <td>
                    <button
                      className={`control-btn${armed === `teardown:${h.uuid}` ? ' danger' : ''}`}
                      disabled={tearingDown.has(h.uuid) || h.status !== 'active'}
                      onClick={() => handleTeardownAll(h)}
                      title="Stop all deckies on this host (keeps it enrolled)"
                    >
                      <PowerOff size={14} />{' '}
                      {tearingDown.has(h.uuid)
                        ? 'Tearing down…'
                        : armed === `teardown:${h.uuid}`
                          ? 'Click again to confirm'
                          : 'Teardown all'}
                    </button>
                    <button
                      className="control-btn danger"
                      disabled={decommissioning.has(h.uuid)}
                      onClick={() => handleDecommission(h)}
                    >
                      <Trash2 size={14} />{' '}
                      {decommissioning.has(h.uuid)
                        ? 'Decommissioning…'
                        : armed === `decom:${h.uuid}`
                          ? 'Click again to confirm'
                          : 'Decommission'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <EnrollmentWizard
        open={showEnroll}
        onClose={() => setShowEnroll(false)}
        onEnrolled={fetchHosts}
      />
    </div>
  );
};

export default SwarmHosts;
