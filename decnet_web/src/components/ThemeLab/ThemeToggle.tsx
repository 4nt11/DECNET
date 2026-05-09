import React, { useEffect, useState } from 'react';

/* Dev-scoped Dark/Light theme toggle for the theme lab.
 *
 * Flips `document.documentElement.dataset.theme` and persists to
 * **sessionStorage** intentionally — the lab is a tab-scoped
 * exploration tool. Global persistence (across reloads, all users)
 * is the user-facing Config toggle that ships in Task 6. */

export const THEME_SESSION_KEY = 'decnet_theme_lab';

export type Theme = 'dark' | 'light';

export function readLabTheme(): Theme {
  try {
    const v = sessionStorage.getItem(THEME_SESSION_KEY);
    return v === 'light' ? 'light' : 'dark';
  } catch {
    return 'dark';
  }
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
}

const ThemeToggle: React.FC = () => {
  const [theme, setTheme] = useState<Theme>(() => readLabTheme());

  useEffect(() => {
    applyTheme(theme);
    try { sessionStorage.setItem(THEME_SESSION_KEY, theme); } catch { /* ignore */ }
  }, [theme]);

  return (
    <div className="lab-theme-toggle" role="group" aria-label="Theme">
      <button
        type="button"
        className={`btn small ${theme === 'dark' ? '' : 'ghost'}`}
        onClick={() => setTheme('dark')}
        aria-pressed={theme === 'dark'}
      >
        DARK
      </button>
      <button
        type="button"
        className={`btn small ${theme === 'light' ? '' : 'ghost'}`}
        onClick={() => setTheme('light')}
        aria-pressed={theme === 'light'}
      >
        LIGHT
      </button>
    </div>
  );
};

export default ThemeToggle;
