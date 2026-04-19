import React, { useEffect, useRef, useState } from 'react';
import api from '../utils/api';
import './Dashboard.css';
import './Swarm.css';
import { UserPlus, Copy, RotateCcw, Check, AlertTriangle } from 'lucide-react';

interface BundleResult {
  token: string;
  host_uuid: string;
  command: string;
  expires_at: string;
}

const AgentEnrollment: React.FC = () => {
  const [masterHost, setMasterHost] = useState(window.location.hostname);
  const [agentName, setAgentName] = useState('');
  const [agentHost, setAgentHost] = useState('');
  const [withUpdater, setWithUpdater] = useState(true);
  const [servicesIni, setServicesIni] = useState<string | null>(null);
  const [servicesIniName, setServicesIniName] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<BundleResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [now, setNow] = useState<number>(Date.now());
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

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

  const reset = () => {
    setResult(null);
    setError(null);
    setAgentName('');
    setAgentHost('');
    setWithUpdater(true);
    setServicesIni(null);
    setServicesIniName(null);
    setCopied(false);
    if (fileRef.current) fileRef.current.value = '';
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const res = await api.post('/swarm/enroll-bundle', {
        master_host: masterHost,
        agent_name: agentName,
        agent_host: agentHost,
        with_updater: withUpdater,
        services_ini: servicesIni,
      });
      setResult(res.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Enrollment bundle creation failed');
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

  const nameOk = /^[a-z0-9][a-z0-9-]{0,62}$/.test(agentName);

  const remainingSecs = result ? Math.max(0, Math.floor((new Date(result.expires_at).getTime() - now) / 1000)) : 0;
  const mm = Math.floor(remainingSecs / 60).toString().padStart(2, '0');
  const ss = (remainingSecs % 60).toString().padStart(2, '0');

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1><UserPlus size={28} /> Agent Enrollment</h1>
      </div>

      {!result ? (
        <div className="panel">
          <p>
            Generates a one-shot bootstrap URL valid for 5 minutes. Paste the command into a
            root shell on the target worker VM — no manual cert shuffling required.
          </p>
          <form onSubmit={submit} className="form-stack">
            <label>
              Master host (IP or DNS this agent can reach)
              <input
                type="text"
                value={masterHost}
                onChange={(e) => setMasterHost(e.target.value)}
                required
              />
            </label>
            <label>
              Agent host (IP or DNS of the new worker VM)
              <input
                type="text"
                value={agentHost}
                onChange={(e) => setAgentHost(e.target.value)}
                placeholder="e.g. 192.168.1.23"
                required
              />
            </label>
            <label>
              Agent name (lowercase, digits, dashes)
              <input
                type="text"
                value={agentName}
                onChange={(e) => setAgentName(e.target.value.toLowerCase())}
                pattern="^[a-z0-9][a-z0-9-]{0,62}$"
                required
              />
              {agentName && !nameOk && (
                <small className="field-warn"><AlertTriangle size={12} /> must match ^[a-z0-9][a-z0-9-]{`{0,62}`}$</small>
              )}
            </label>
            <label className="form-inline">
              <input
                type="checkbox"
                checked={withUpdater}
                onChange={(e) => setWithUpdater(e.target.checked)}
              />
              <span>Install updater daemon (lets the master push code updates to this agent)</span>
            </label>
            <label>
              Services INI (optional)
              <input ref={fileRef} type="file" accept=".ini,.conf,.txt" onChange={handleFile} />
              {servicesIniName && <small>loaded: {servicesIniName}</small>}
            </label>
            {error && <div className="error-box">{error}</div>}
            <button
              type="submit"
              className="control-btn primary"
              disabled={submitting || !nameOk || !masterHost || !agentHost}
            >
              {submitting ? 'Generating…' : 'Generate enrollment bundle'}
            </button>
          </form>
        </div>
      ) : (
        <div className="panel">
          <h3>Paste this on the new worker (as root):</h3>
          <pre className="code-block">{result.command}</pre>
          <div className="button-row">
            <button className="control-btn" onClick={copyCmd}>
              {copied ? <><Check size={14} /> Copied</> : <><Copy size={14} /> Copy</>}
            </button>
            <button className="control-btn" onClick={reset}>
              <RotateCcw size={14} /> Generate another
            </button>
          </div>
          <p>
            Expires in <strong>{mm}:{ss}</strong> — one-shot, single download. Host UUID:{' '}
            <code>{result.host_uuid}</code>
          </p>
          {remainingSecs === 0 && (
            <div className="error-box">
              <AlertTriangle size={14} /> This bundle has expired. Generate another.
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default AgentEnrollment;
