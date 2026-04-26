import React from 'react';
import { useNavigate } from 'react-router-dom';
import { X, Lock, Copy, Check } from '../icons';
import { useToast } from './Toasts/useToast';

export interface CredentialReuseRow {
  id: string;
  secret_sha256: string;
  secret_kind: string;
  principal: string | null;
  principal_key: string;
  attacker_uuids: string[];
  attacker_ips: string[];
  deckies: string[];
  services: string[];
  target_count: number;
  attempt_count: number;
  confidence: number;
  first_seen: string;
  last_seen: string;
  updated_at: string;
  secret_printable: string | null;
  secret_b64: string | null;
}

interface Props {
  row: CredentialReuseRow;
  onClose: () => void;
}

const CredentialReuseInspector: React.FC<Props> = ({ row, onClose }) => {
  const { push } = useToast();
  const navigate = useNavigate();
  const isPlain = row.secret_kind === 'plaintext';

  const copy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      push({ text: `${label} COPIED`, tone: 'matrix', icon: 'copy' });
    } catch {
      push({ text: 'CLIPBOARD BLOCKED', tone: 'alert', icon: 'alert-triangle' });
    }
  };

  return (
    <div
      className="credentials-drawer-backdrop"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="credentials-drawer">
        <div className="bd-head">
          <h3>
            <Lock size={14} />
            <span>REUSE #{row.id.slice(0, 8)}</span>
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
                {row.secret_kind.toUpperCase()}
              </span>
            </div>
            <div className="k">PRINCIPAL</div>
            <div className="v">{row.principal ?? <span className="dim">—</span>}</div>
            <div className="k">TARGETS</div>
            <div className="v"><span className="attempt-pill">{row.target_count}</span></div>
            <div className="k">ATTEMPTS</div>
            <div className="v">{row.attempt_count}</div>
            <div className="k">CONFIDENCE</div>
            <div className="v">{row.confidence.toFixed(2)}</div>
            <div className="k">FIRST SEEN</div>
            <div className="v">{new Date(row.first_seen).toLocaleString()}</div>
            <div className="k">LAST SEEN</div>
            <div className="v">{new Date(row.last_seen).toLocaleString()}</div>
          </div>

          <div>
            <div className="type-label">DECKIES × SERVICES</div>
            <div className="logs-table-container">
              <table className="logs-table">
                <thead>
                  <tr>
                    <th></th>
                    {row.services.map(svc => (
                      <th key={svc}>{svc.toUpperCase()}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {row.deckies.map(decky => (
                    <tr key={decky}>
                      <td className="violet-accent">{decky}</td>
                      {row.services.map(svc => (
                        <td key={svc} style={{ textAlign: 'center' }}>
                          <Check size={12} className="matrix-text" />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <div className="type-label">ATTACKERS</div>
            {row.attacker_uuids.length === 0 ? (
              <div className="dim" style={{ fontSize: '0.75rem', padding: '6px 0' }}>
                PROFILING PENDING — credential captures precede attacker
                profiling; this row will populate once the profiler runs.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {row.attacker_uuids.map((uuid, i) => (
                  <div
                    key={uuid}
                    onClick={() => navigate(`/attackers/${uuid}`)}
                    style={{
                      display: 'flex',
                      gap: 8,
                      alignItems: 'baseline',
                      cursor: 'pointer',
                      textDecoration: 'underline dotted',
                    }}
                  >
                    <span className="matrix-text">{uuid.slice(0, 8)}</span>
                    <span className="dim" style={{ fontSize: '0.72rem' }}>
                      {row.attacker_ips[i] ?? ''}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div>
            <div className="type-label">{isPlain ? 'PLAINTEXT SECRET' : 'OBSERVED RESPONSE'}</div>
            <pre className="code-block">
              <span className="ck">printable:</span>{' '}
              <span className="cs">{row.secret_printable ?? '—'}</span>{'\n'}
              <span className="ck">b64:</span>{' '}
              <span className="cs">{row.secret_b64 ?? '—'}</span>
            </pre>
          </div>

          <div>
            <div className="type-label">SECRET SHA-256</div>
            <div className="hash-row">
              <span className="hash-text">{row.secret_sha256}</span>
              <button
                className="icon-btn"
                onClick={() => copy(row.secret_sha256, 'HASH')}
                aria-label="Copy hash"
              >
                <Copy size={12} />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CredentialReuseInspector;
