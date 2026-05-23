// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useRef, useState } from 'react';
import Modal from '../Modal/Modal';
import {
  AlertTriangle, Check, Copy, RotateCcw, UserPlus,
} from '../../icons';
import {
  AGENT_NAME_RE, bundleSecondsLeft, extractErrorDetail, formatMmSs,
} from './helpers';
import type { BundleRequest, BundleResult } from './types';

interface Props {
  open: boolean;
  onClose: () => void;
  onEnrolled: () => void;
  /** Injected so the page can swap in the {ok, reason} hook
   *  contract without the wizard knowing about axios. */
  generateBundle: (req: BundleRequest) => Promise<{ ok: true; data: BundleResult } | { ok: false; reason: string }>;
}

const EnrollmentWizard: React.FC<Props> = ({ open, onClose, onEnrolled, generateBundle }) => {
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

  const nameOk = AGENT_NAME_RE.test(agentName);

  const generate = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const r = await generateBundle({
        master_host: masterHost,
        agent_name: agentName,
        with_updater: withUpdater,
        use_ipvlan: useIpvlan,
        services_ini: servicesIni,
      });
      if (r.ok) {
        setResult(r.data);
        onEnrolled();
      } else {
        setError(r.reason);
      }
    } catch (err) {
      setError(extractErrorDetail(err, 'Enrollment bundle creation failed'));
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

  const remainingSecs = result ? bundleSecondsLeft(result.expires_at, now) : 0;
  const { mm, ss } = formatMmSs(remainingSecs);

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

export default EnrollmentWizard;
