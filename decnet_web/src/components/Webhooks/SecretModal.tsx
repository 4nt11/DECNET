import React, { useState } from 'react';
import { AlertTriangle, Check, Copy } from '../../icons';

interface Props {
  name: string;
  secret: string;
  onClose: () => void;
}

const SecretModal: React.FC<Props> = ({ name, secret, onClose }) => {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* no-op — browsers without clipboard perms will just see no feedback */
    }
  };
  return (
    <div
      className="wh-secret-modal-backdrop"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="wh-secret-modal">
        <h3>WEBHOOK SECRET · {name.toUpperCase()}</h3>
        <div className="wh-secret-warn">
          <AlertTriangle size={14} />
          <span>COPY THIS NOW — IT WILL NOT BE SHOWN AGAIN. THE HMAC ON EVERY DELIVERY IS SIGNED WITH THIS VALUE.</span>
        </div>
        <div className="wh-secret-value">{secret}</div>
        <div className="wh-secret-actions">
          <button className="btn ghost" onClick={copy}>
            <Copy size={12} /> {copied ? 'COPIED' : 'COPY'}
          </button>
          <button className="btn violet" onClick={onClose}>
            <Check size={12} /> DONE
          </button>
        </div>
      </div>
    </div>
  );
};

export default SecretModal;
