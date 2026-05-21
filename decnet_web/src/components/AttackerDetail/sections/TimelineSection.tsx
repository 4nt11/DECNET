import React, { useState } from 'react';
import { Section, Tag } from '../ui';
import type { AttackerData } from '../types';

const ROTATION_THRESHOLD = 20;
const INLINE_LIMIT = 1;

interface LeakedIPsRowProps {
  leaks: NonNullable<AttackerData['ip_leaks']>;
  total: number;
}

/** "LEAKED IPs" inline list with rotation-detection badge. The
 *  backend caps the server-side sample at 10 rows; `total` is the
 *  unbounded count, which may exceed what we have actual IP values
 *  for. Past ROTATION_THRESHOLD distinct claims, badge in red — that
 *  pattern is XFF-rotation / WAF-bypass probing, not real
 *  attribution leakage. */
const LeakedIPsRow: React.FC<LeakedIPsRowProps> = ({ leaks, total }) => {
  const [expanded, setExpanded] = useState(false);
  const distinctIPs = Array.from(
    new Set(
      leaks
        .map((l) => l.payload?.real_ip_claim)
        .filter((v): v is string => !!v),
    ),
  );
  const rotationDetected = total >= ROTATION_THRESHOLD;
  const visible = expanded ? distinctIPs : distinctIPs.slice(0, INLINE_LIMIT);
  const hiddenInList = distinctIPs.length - visible.length;
  const remainingBeyondSample = total - distinctIPs.length;

  const ipTooltip = (ip: string): string => {
    const latest = leaks.find((l) => l.payload?.real_ip_claim === ip);
    return latest
      ? `Leaked via ${latest.payload.source_header ?? '?'}; source ${latest.payload.source_ip ?? '?'}`
      : '';
  };

  return (
    <div>
      <span className="dim" style={{ color: 'var(--warn, #e0a040)' }}>
        LEAKED IPs:{' '}
      </span>
      {rotationDetected && (
        <span
          style={{ marginRight: 8, display: 'inline-block' }}
          title={`${total} distinct claimed IPs — almost certainly XFF-rotation / WAF-bypass probing, not a real attribution leak.`}
        >
          <Tag color="var(--alert, #ff4d4d)">
            ROTATION · {total}
          </Tag>
        </span>
      )}
      {visible.map((ip, i, arr) => (
        <span
          key={ip}
          style={{ color: 'var(--warn, #e0a040)', fontFamily: 'monospace' }}
          title={ipTooltip(ip)}
        >
          {ip}
          {i < arr.length - 1 ? ', ' : ''}
        </span>
      ))}
      {!expanded && hiddenInList > 0 && (
        <>
          {' '}
          <button
            onClick={() => setExpanded(true)}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--warn, #e0a040)',
              cursor: 'pointer',
              padding: 0,
              fontFamily: 'inherit',
              textDecoration: 'underline',
            }}
          >
            + {hiddenInList} more
          </button>
        </>
      )}
      {remainingBeyondSample > 0 && (
        <span
          className="dim"
          style={{ marginLeft: 6, fontSize: '0.75rem' }}
          title="Only the 10 most-recent claimed IPs are fetched; the total count is the full DB tally."
        >
          (+{remainingBeyondSample} beyond sample)
        </span>
      )}
      {expanded && hiddenInList === 0 && distinctIPs.length > INLINE_LIMIT && (
        <>
          {' '}
          <button
            onClick={() => setExpanded(false)}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--accent-color)',
              cursor: 'pointer',
              padding: 0,
              fontFamily: 'inherit',
              textDecoration: 'underline',
            }}
          >
            collapse
          </button>
        </>
      )}
    </div>
  );
};

interface Props {
  attacker: AttackerData;
  open: boolean;
  onToggle: () => void;
}

/** TIMELINE collapsible — first/last seen, ASN/origin, reverse DNS,
 *  and leaked-IP row when the attacker has any ip_leaks. */
export const TimelineSection: React.FC<Props> = ({ attacker, open, onToggle }) => (
  <Section title="TIMELINE" open={open} onToggle={onToggle}>
    <div
      style={{
        padding: '16px',
        display: 'flex',
        flexWrap: 'wrap',
        gap: '32px',
        fontSize: '0.85rem',
      }}
    >
      <div>
        <span className="dim">FIRST SEEN: </span>
        <span className="matrix-text">{new Date(attacker.first_seen).toLocaleString()}</span>
      </div>
      <div>
        <span className="dim">LAST SEEN: </span>
        <span className="matrix-text">{new Date(attacker.last_seen).toLocaleString()}</span>
      </div>
      <div>
        <span className="dim">UPDATED: </span>
        <span className="dim">{new Date(attacker.updated_at).toLocaleString()}</span>
      </div>
      <div>
        <span className="dim">ORIGIN: </span>
        {attacker.country_code ? (
          <span className="matrix-text">
            {attacker.country_code}
            {attacker.country_source && (
              <span className="dim" style={{ marginLeft: 6, fontSize: '0.75rem' }}>
                ({attacker.country_source})
              </span>
            )}
          </span>
        ) : (
          <span className="dim">unknown</span>
        )}
      </div>
      <div>
        <span className="dim">AS: </span>
        {attacker.asn != null ? (
          <span className="matrix-text">
            AS{attacker.asn}
            {attacker.bgp_prefix && (
              <span className="dim" style={{ marginLeft: 6, fontSize: '0.75rem', fontFamily: 'monospace' }}>
                {attacker.bgp_prefix}
              </span>
            )}
            {attacker.as_name && (
              <span className="dim" style={{ marginLeft: 6, fontSize: '0.75rem' }}>
                {attacker.as_name}
              </span>
            )}
            {attacker.asn_source && (
              <span className="dim" style={{ marginLeft: 6, fontSize: '0.75rem' }}>
                ({attacker.asn_source})
              </span>
            )}
            {attacker.rpki_status === 'valid' && (
              <span className="rpki-status-badge valid" style={{ marginLeft: 8 }}>RPKI VALID</span>
            )}
            {attacker.rpki_status === 'invalid' && (
              <span className="rpki-status-badge invalid" style={{ marginLeft: 8 }}>RPKI INVALID</span>
            )}
            {attacker.rpki_status === 'not-found' && (
              <span className="dim" style={{ marginLeft: 8, fontSize: '0.7rem' }}>RPKI NO ROA</span>
            )}
          </span>
        ) : (
          <span className="dim">unknown</span>
        )}
      </div>
      <div>
        <span className="dim">REVERSE DNS: </span>
        {attacker.ptr_record ? (
          <span
            className="matrix-text"
            style={{ fontFamily: 'monospace' }}
            title="One-shot PTR record resolved at first sighting."
          >
            {attacker.ptr_record}
          </span>
        ) : (
          <span className="dim">—</span>
        )}
      </div>
      {attacker.ip_leaks && attacker.ip_leaks.length > 0 && (
        <LeakedIPsRow
          leaks={attacker.ip_leaks}
          total={attacker.ip_leaks_total ?? attacker.ip_leaks.length}
        />
      )}
    </div>
  </Section>
);
