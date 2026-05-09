import React from 'react';
import { Section } from '../ui';
import type { AttackerData } from '../types';

interface Props {
  attacker: AttackerData;
  serviceFilter: string | null;
  setServiceFilter: (s: string | null) => void;
  open: boolean;
  onToggle: () => void;
}

/** SERVICES TARGETED collapsible — interactive service-tag chips
 *  with two-tone styling (interacted vs. scan-only) plus a click
 *  filter. Selection state lives in the page-level data hook so
 *  CommandsViewer can subscribe to the same filter. */
export const ServicesTargeted: React.FC<Props> = ({
  attacker,
  serviceFilter,
  setServiceFilter,
  open,
  onToggle,
}) => (
  <Section title="SERVICES TARGETED" open={open} onToggle={onToggle}>
    <div style={{ padding: '16px' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
        {attacker.services.length > 0 ? (
          attacker.services.map((svc) => {
            const isActive = serviceFilter === svc;
            const interacted =
              attacker.service_activity?.interacted.includes(svc) ?? false;
            const baseStyle: React.CSSProperties = interacted
              ? {
                  borderColor: 'var(--accent-color)',
                  color: 'var(--accent-color)',
                  background: 'var(--violet-tint-10)',
                }
              : { opacity: 0.55 };
            const activeStyle: React.CSSProperties = isActive
              ? interacted
                ? {
                    backgroundColor: 'var(--accent-color)',
                    color: 'var(--bg-color)',
                    borderColor: 'var(--accent-color)',
                    opacity: 1,
                  }
                : {
                    backgroundColor: 'var(--text-color)',
                    color: 'var(--bg-color)',
                    borderColor: 'var(--text-color)',
                    opacity: 1,
                  }
              : {};
            return (
              <span
                key={svc}
                className="service-badge"
                style={{
                  fontSize: '0.85rem',
                  padding: '4px 12px',
                  cursor: 'pointer',
                  ...baseStyle,
                  ...activeStyle,
                }}
                onClick={() => setServiceFilter(isActive ? null : svc)}
                title={
                  isActive
                    ? 'Clear filter'
                    : `Filter by ${svc.toUpperCase()} — ${interacted ? 'interacted with' : 'scanned only'}`
                }
              >
                {interacted ? '· ' : ''}{svc.toUpperCase()}
              </span>
            );
          })
        ) : (
          <span className="dim">No services recorded</span>
        )}
      </div>
      {attacker.services.length > 0 && (
        <div
          style={{
            marginTop: '12px',
            fontSize: '0.7rem',
            display: 'flex',
            gap: '16px',
          }}
        >
          <span style={{ color: 'var(--accent-color)' }}>· INTERACTED</span>
          <span className="dim">SCAN-ONLY</span>
        </div>
      )}
    </div>
  </Section>
);
