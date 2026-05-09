import React from 'react';
import { ChevronDown, ChevronUp } from '../../icons';

/** Pill-style tag chip used throughout the AttackerDetail surface
 *  for badges, filters, and category labels. Color drives both the
 *  border and a 15%-alpha fill (the suffix is hex alpha). */
export const Tag: React.FC<{ children: React.ReactNode; color?: string }> = ({
  children,
  color,
}) => (
  <span
    style={{
      fontSize: '0.7rem',
      padding: '2px 8px',
      letterSpacing: '1px',
      border: `1px solid ${color || 'var(--text-color)'}`,
      color: color || 'var(--text-color)',
      background: `${color || 'var(--text-color)'}15`,
    }}
  >
    {children}
  </span>
);

/** Collapsible panel used by every section on the AttackerDetail page.
 *  The header is the toggle; an optional `right` slot hosts controls
 *  (filters, action buttons) whose clicks are stopped from bubbling
 *  to the toggle handler. */
export const Section: React.FC<{
  title: React.ReactNode;
  right?: React.ReactNode;
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}> = ({ title, right, open, onToggle, children }) => (
  <div className="logs-section">
    <div
      className="section-header"
      style={{ justifyContent: 'space-between', cursor: 'pointer', userSelect: 'none' }}
      onClick={onToggle}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        {open ? <ChevronUp size={16} className="dim" /> : <ChevronDown size={16} className="dim" />}
        <h2>{title}</h2>
      </div>
      {right && <div onClick={(e) => e.stopPropagation()}>{right}</div>}
    </div>
    {open && children}
  </div>
);
