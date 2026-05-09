import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Crosshair, Download } from '../../../icons';
import { Tag } from '../ui';
import api from '../../../utils/api';
import type { AttackerData } from '../types';

interface Props {
  attacker: AttackerData;
}

/** Page header: crosshair + IP + country / traversal / identity badges.
 *  The identity badge is click-through to the resolved-actor page. */
export const AttackerHeader: React.FC<Props> = ({ attacker }) => {
  const navigate = useNavigate();

  const handleStixDownload = async () => {
    try {
      const res = await api.get(`/attackers/${attacker.uuid}/export/stix`, { responseType: 'blob' });
      const href = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = href;
      a.download = `decnet-attacker-${attacker.uuid.slice(0, 8)}.stix.json`;
      a.click();
      URL.revokeObjectURL(href);
    } catch {
      // best-effort
    }
  };
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
      <Crosshair size={32} className="violet-accent" />
      <h1 className="matrix-text" style={{ fontSize: '1.8rem', letterSpacing: '2px' }}>
        {attacker.ip}
      </h1>
      {attacker.country_code && (
        <Tag color="var(--text-color)">
          <span
            title={attacker.country_source ? `source: ${attacker.country_source}` : undefined}
            style={{ letterSpacing: '2px' }}
          >
            {attacker.country_code}
          </span>
        </Tag>
      )}
      {attacker.is_traversal && (
        <span className="traversal-badge" style={{ fontSize: '0.8rem' }}>TRAVERSAL</span>
      )}
      {attacker.identity_id && (
        <span
          className="traversal-badge"
          style={{
            fontSize: '0.8rem',
            cursor: 'pointer',
            letterSpacing: '2px',
          }}
          title="Resolved identity — click to view all observations linked to this actor"
          onClick={() => navigate(`/identities/${attacker.identity_id}`)}
        >
          IDENTITY · {attacker.identity_id.slice(0, 8)}
        </span>
      )}
      <button
        type="button"
        className="btn"
        style={{ marginLeft: 'auto' }}
        title="Download STIX 2.1 bundle for this attacker"
        onClick={handleStixDownload}
      >
        <Download size={12} />
        <span style={{ marginLeft: 6 }}>STIX</span>
      </button>
    </div>
  );
};
