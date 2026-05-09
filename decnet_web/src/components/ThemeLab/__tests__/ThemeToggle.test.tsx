import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ThemeToggle, {
  THEME_SESSION_KEY,
  readLabTheme,
  applyTheme,
} from '../ThemeToggle';

describe('ThemeToggle', () => {
  beforeEach(() => {
    sessionStorage.clear();
    delete document.documentElement.dataset.theme;
  });

  it('defaults to dark and applies dark on mount', () => {
    render(<ThemeToggle />);
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(sessionStorage.getItem(THEME_SESSION_KEY)).toBe('dark');
    expect(screen.getByRole('button', { name: 'DARK' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
  });

  it('flips to light on click and persists to sessionStorage', async () => {
    const user = userEvent.setup();
    render(<ThemeToggle />);
    await user.click(screen.getByRole('button', { name: 'LIGHT' }));
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(sessionStorage.getItem(THEME_SESSION_KEY)).toBe('light');
    expect(screen.getByRole('button', { name: 'LIGHT' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
  });

  it('hydrates from existing sessionStorage value', () => {
    sessionStorage.setItem(THEME_SESSION_KEY, 'light');
    render(<ThemeToggle />);
    expect(document.documentElement.dataset.theme).toBe('light');
  });

  it('readLabTheme falls back to dark on bad value', () => {
    sessionStorage.setItem(THEME_SESSION_KEY, 'banana');
    expect(readLabTheme()).toBe('dark');
  });

  it('applyTheme writes the html attribute', () => {
    applyTheme('light');
    expect(document.documentElement.dataset.theme).toBe('light');
    applyTheme('dark');
    expect(document.documentElement.dataset.theme).toBe('dark');
  });
});
