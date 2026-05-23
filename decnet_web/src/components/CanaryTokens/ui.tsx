// SPDX-License-Identifier: AGPL-3.0-or-later
import React from 'react';

export const INPUT_STYLE: React.CSSProperties = {
  width: '100%',
  padding: '8px 10px',
  marginBottom: '12px',
  background: 'var(--matrix-tint-5)',
  border: '1px solid var(--border-color, #30363d)',
  color: 'var(--text-color)',
  fontSize: '0.85rem',
};

export const BTN_PRIMARY: React.CSSProperties = {
  padding: '8px 14px',
  border: '1px solid var(--accent-color, #00ff88)',
  background: 'var(--accent-color, #00ff88)',
  color: 'var(--bg-color, #0d1117)',
  cursor: 'pointer',
  fontSize: '0.8rem',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  fontWeight: 'bold',
};

export const BTN_GHOST: React.CSSProperties = {
  padding: '8px 14px',
  border: '1px solid var(--text-color)',
  background: 'transparent',
  color: 'var(--text-color)',
  cursor: 'pointer',
  fontSize: '0.8rem',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
};

export const Field: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div>
    <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', letterSpacing: '0.1em', marginBottom: '4px' }}>
      {label.toUpperCase()}
    </div>
    {children}
  </div>
);

export const Stat: React.FC<{ label: string; value: number | string; color: string }> = ({ label, value, color }) => (
  <div style={{
    flex: '1 1 120px',
    padding: '12px 16px',
    border: '1px solid var(--border-color, #30363d)',
    background: 'var(--matrix-tint-5)',
  }}>
    <div style={{ fontSize: '0.7rem', color: 'var(--dim-color)', letterSpacing: '0.1em' }}>{label}</div>
    <div style={{ fontSize: '1.4rem', fontWeight: 'bold', color, marginTop: '4px' }}>{value}</div>
  </div>
);
