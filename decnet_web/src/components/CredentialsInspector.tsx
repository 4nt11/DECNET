// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';
import { X, Lock, Copy, Send, Ban } from '../icons';
import { useToast } from './Toasts/useToast';

export interface CredentialEntry {
  id: number;
  attacker_ip: string;
  decky_name: string;
  service: string;
  principal: string | null;
  secret_kind: string;
  secret_sha256: string;
  secret_b64: string | null;
  secret_printable: string | null;
  outcome: string | null;
  fields: any;
  first_seen: string;
  last_seen: string;
  attempt_count: number;
}

interface Props {
  cred: CredentialEntry;
  onClose: () => void;
  onSelectAttacker: (ip: string) => void;
}

const CredentialsInspector: React.FC<Props> = ({ cred, onClose, onSelectAttacker }) => {
  const { push } = useToast();
  const isPlain = cred.secret_kind === 'plaintext';

  const copy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      push({ text: `${label} COPIED`, tone: 'matrix', icon: 'copy' });
    } catch {
      push({ text: 'CLIPBOARD BLOCKED', tone: 'alert', icon: 'alert-triangle' });
    }
  };

  const copyJson = () => copy(JSON.stringify(cred, null, 2), 'JSON');
  const stubMisp = () => push({ text: 'MISP NOT CONFIGURED', tone: 'violet', icon: 'info' });
  const stubBlocklist = () => push({ text: 'BLOCKLIST NOT WIRED', tone: 'violet', icon: 'info' });

  return (
    <div
      className="credentials-drawer-backdrop"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="credentials-drawer">
        <div className="bd-head">
          <h3>
            <Lock size={14} />
            <span>CREDENTIAL #{cred.id}</span>
          </h3>
          <button className="close-btn" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="bd-body">
          <div className="kvs">
            <div className="k">SECRET KIND</div>
            <div className="v">
              <span className={`chip ${isPlain ? 'matrix' : 'violet'}`}>
                {cred.secret_kind.toUpperCase()}
              </span>
            </div>
            <div className="k">OUTCOME</div>
            <div className="v">
              {cred.outcome
                ? <span className="chip dim-chip">{cred.outcome.toUpperCase()}</span>
                : <span className="dim">—</span>}
            </div>
            <div className="k">DECKY</div>
            <div className="v violet-accent">{cred.decky_name}</div>
            <div className="k">SERVICE</div>
            <div className="v"><span className="chip dim-chip">{cred.service}</span></div>
            <div className="k">PRINCIPAL</div>
            <div className="v">{cred.principal ?? <span className="dim">—</span>}</div>
            <div className="k">ATTACKER</div>
            <div className="v">
              <span
                className="attacker-link"
                onClick={() => onSelectAttacker(cred.attacker_ip)}
              >
                {cred.attacker_ip}
              </span>
            </div>
            <div className="k">ATTEMPTS</div>
            <div className="v">{cred.attempt_count}</div>
            <div className="k">FIRST SEEN</div>
            <div className="v">{new Date(cred.first_seen).toLocaleString()}</div>
            <div className="k">LAST SEEN</div>
            <div className="v">{new Date(cred.last_seen).toLocaleString()}</div>
          </div>

          <div>
            <div className="type-label">{isPlain ? 'PLAINTEXT SECRET' : 'OBSERVED RESPONSE'}</div>
            <pre className="code-block">
              <span className="ck">printable:</span>{' '}
              <span className="cs">{cred.secret_printable ?? '—'}</span>{'\n'}
              <span className="ck">b64:</span>{' '}
              <span className="cs">{cred.secret_b64 ?? '—'}</span>
            </pre>
          </div>

          <div>
            <div className="type-label">SECRET SHA-256</div>
            <div className="hash-row">
              <span className="hash-text">{cred.secret_sha256}</span>
              <button
                className="icon-btn"
                onClick={() => copy(cred.secret_sha256, 'HASH')}
                aria-label="Copy hash"
              >
                <Copy size={12} />
              </button>
            </div>
          </div>

          {cred.fields && Object.keys(cred.fields || {}).length > 0 && (
            <div>
              <div className="type-label">SERVICE FIELDS</div>
              <pre className="code-block">{JSON.stringify(cred.fields, null, 2)}</pre>
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

export default CredentialsInspector;
