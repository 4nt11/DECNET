// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from 'react';
import { useToast } from '../../Toasts/useToast';

const TWEAKS_KEY = 'decnet_tweaks';

export type Accent = 'matrix' | 'violet';

const loadInitialAccent = (): Accent => {
  try {
    const raw = localStorage.getItem(TWEAKS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed?.accent === 'violet') return 'violet';
    }
  } catch { /* noop */ }
  return 'matrix';
};

const persistAccent = (value: Accent): void => {
  let existing: Record<string, unknown> = {};
  try {
    const raw = localStorage.getItem(TWEAKS_KEY);
    if (raw) existing = JSON.parse(raw) ?? {};
  } catch { existing = {}; }
  localStorage.setItem(TWEAKS_KEY, JSON.stringify({ ...existing, accent: value }));
  document.documentElement.setAttribute('data-accent', value);
};

/** APPEARANCE tab — accent-color picker. State is owned here because
 *  no other Config tab cares about the choice; it persists to
 *  localStorage and flips the data-accent attribute on <html>. */
export const AppearanceTab: React.FC = () => {
  const [accent, setAccent] = useState<Accent>(loadInitialAccent);
  const { push: pushToast } = useToast();

  const handleAccentChange = (value: Accent) => {
    setAccent(value);
    persistAccent(value);
    pushToast({ text: `ACCENT · ${value.toUpperCase()}`, icon: 'check-circle', tone: 'violet' });
  };

  return (
    <div className="config-panel">
      <div className="config-field">
        <span className="config-label">ACCENT COLOR</span>
        <p style={{ fontSize: '0.75rem', opacity: 0.5, margin: '4px 0 12px' }}>
          Swaps the UI accent (nav bars, hover glows, chip borders) between matrix-green and electric-violet. Persists per-browser.
        </p>
        <div style={{ display: 'flex', gap: '8px' }}>
          {(['matrix', 'violet'] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => handleAccentChange(value)}
              className="save-btn"
              style={{
                padding: '8px 16px',
                fontSize: '0.75rem',
                letterSpacing: '1.5px',
                borderColor: accent === value
                  ? (value === 'violet' ? 'var(--violet)' : 'var(--matrix)')
                  : 'var(--border)',
                color: accent === value
                  ? (value === 'violet' ? 'var(--violet)' : 'var(--matrix)')
                  : 'var(--matrix)',
                opacity: accent === value ? 1 : 0.6,
                background: 'transparent',
              }}
            >
              {accent === value ? '● ' : '○ '}
              {value.toUpperCase()}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
