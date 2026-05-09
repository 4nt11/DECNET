import React from 'react';

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
