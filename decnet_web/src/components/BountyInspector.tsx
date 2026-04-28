import React from 'react';
import { X, Key, Package, Copy, Send, Ban } from '../icons';
import { useToast } from './Toasts/useToast';

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
  const Icon = isCred ? Key : Package;
  const p = bounty.payload || {};

  const copyJson = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(bounty, null, 2));
      push({ text: 'JSON COPIED', tone: 'matrix', icon: 'copy' });
    } catch {
      push({ text: 'CLIPBOARD BLOCKED', tone: 'alert', icon: 'alert-triangle' });
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
              <span className={`chip ${isCred ? 'matrix' : 'violet'}`}>{bounty.bounty_type.toUpperCase()}</span>
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
            <div className="type-label">{isCred ? 'CAPTURED CREDENTIAL' : 'CAPTURED PAYLOAD'}</div>
            {isCred ? (
              <pre className="code-block">
                <span className="ck">username:</span> <span className="cs">{p.username}</span>{'\n'}
                <span className="ck">password:</span> <span className="cs">{p.password}</span>
              </pre>
            ) : (
              <pre className="code-block">{JSON.stringify(p, null, 2)}</pre>
            )}
          </div>

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
