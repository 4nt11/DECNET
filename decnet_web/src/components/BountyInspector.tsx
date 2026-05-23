// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from 'react';
import { X, Key, Package, Copy, Send, Ban, FileText, Mail, Download, AlertTriangle } from '../icons';
import { useToast } from './Toasts/useToast';
import api from '../utils/api';

interface BountyEntry {
  id: number;
  timestamp: string;
  decky: string;
  service: string;
  attacker_ip: string;
  bounty_type: string;
  payload: any;
}

interface Props {
  bounty: BountyEntry;
  onClose: () => void;
  onSelectAttacker: (ip: string) => void;
}

const BountyInspector: React.FC<Props> = ({ bounty, onClose, onSelectAttacker }) => {
  const { push } = useToast();
  const isCred = bounty.bounty_type === 'credential';
  const isArt = bounty.bounty_type === 'artifact';
  const p = bounty.payload || {};
  const isMail = isArt && p.kind === 'mail';
  const Icon = isCred ? Key : isMail ? Mail : isArt ? FileText : Package;
  const storedAs: string | undefined = isArt ? p.stored_as : undefined;

  const [downloading, setDownloading] = useState(false);
  const [dlError, setDlError] = useState<string | null>(null);

  const copyJson = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(bounty, null, 2));
      push({ text: 'JSON COPIED', tone: 'matrix', icon: 'copy' });
    } catch {
      push({ text: 'CLIPBOARD BLOCKED', tone: 'alert', icon: 'alert-triangle' });
    }
  };

  const downloadArtifact = async () => {
    if (!storedAs) return;
    setDownloading(true);
    setDlError(null);
    try {
      const res = await api.get(
        `/artifacts/${encodeURIComponent(bounty.decky)}/${encodeURIComponent(storedAs)}?service=${encodeURIComponent(bounty.service)}`,
        { responseType: 'blob' },
      );
      const blobUrl = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = storedAs;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(blobUrl);
    } catch (err: any) {
      const status = err?.response?.status;
      setDlError(
        status === 403 ? 'Admin role required to download artifacts.' :
        status === 404 ? 'Artifact not found on disk (may have been purged).' :
        status === 400 ? 'Server rejected the request (invalid parameters).' :
        'Download failed — see console.'
      );
      console.error('artifact download failed', err);
    } finally {
      setDownloading(false);
    }
  };

  const stubMisp = () => push({ text: 'MISP NOT CONFIGURED', tone: 'violet', icon: 'info' });
  const stubBlocklist = () => push({ text: 'BLOCKLIST NOT WIRED', tone: 'violet', icon: 'info' });

  return (
    <div className="bounty-drawer-backdrop" onClick={onClose}>
      <div className="bounty-drawer" onClick={(e) => e.stopPropagation()}>
        <div className="bd-head">
          <h3>
            <Icon size={14} />
            <span>ARTIFACT #{bounty.id}</span>
          </h3>
          <button className="close-btn" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="bd-body">
          <div className="kvs">
            <div className="k">TYPE</div>
            <div className="v">
              <span className={`chip ${isCred ? 'matrix' : 'violet'}`}>
                <Icon size={9} style={{ marginRight: 4 }} />
                {bounty.bounty_type.toUpperCase()}{isMail ? ' · MAIL' : ''}
              </span>
            </div>
            <div className="k">TIMESTAMP</div>
            <div className="v">{new Date(bounty.timestamp).toLocaleString()}</div>
            <div className="k">DECKY</div>
            <div className="v violet-accent">{bounty.decky}</div>
            <div className="k">SERVICE</div>
            <div className="v"><span className="chip dim-chip">{bounty.service}</span></div>
            <div className="k">ATTACKER</div>
            <div className="v">
              <span
                className="attacker-link"
                onClick={() => onSelectAttacker(bounty.attacker_ip)}
              >
                {bounty.attacker_ip}
              </span>
            </div>
          </div>

          <div>
            <div className="type-label">
              {isCred ? 'CAPTURED CREDENTIAL' : isMail ? 'CAPTURED MESSAGE' : isArt ? 'CAPTURED FILE' : 'CAPTURED PAYLOAD'}
            </div>
            {isCred ? (
              <pre className="code-block">
                <span className="ck">username:</span> <span className="cs">{p.username}</span>{'\n'}
                <span className="ck">password:</span> <span className="cs">{p.password}</span>
              </pre>
            ) : (
              <pre className="code-block">{JSON.stringify(p, null, 2)}</pre>
            )}
          </div>

          {isArt && storedAs && (
            <div>
              <div className="type-label">RAW BYTES</div>
              <div
                className="info-banner"
                style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}
              >
                <AlertTriangle size={14} />
                <span>Attacker-controlled content. Download at your own risk.</span>
              </div>
              <div className="bd-actions">
                <button
                  className="btn"
                  onClick={downloadArtifact}
                  disabled={downloading}
                  style={{ cursor: downloading ? 'wait' : 'pointer', opacity: downloading ? 0.5 : 1 }}
                >
                  <Download size={12} /> {downloading ? 'DOWNLOADING…' : 'DOWNLOAD RAW'}
                </button>
              </div>
              {dlError && (
                <div style={{ color: 'var(--alert)', fontSize: '0.75rem', marginTop: 8 }}>
                  {dlError}
                </div>
              )}
            </div>
          )}

          <div>
            <div className="type-label">EXPORT</div>
            <div className="bd-actions">
              <button className="btn ghost" onClick={copyJson}><Copy size={12} /> COPY JSON</button>
              <button className="btn ghost" onClick={stubMisp}><Send size={12} /> SEND TO MISP</button>
              <button className="btn ghost" onClick={stubBlocklist}><Ban size={12} /> BLOCKLIST IP</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BountyInspector;
