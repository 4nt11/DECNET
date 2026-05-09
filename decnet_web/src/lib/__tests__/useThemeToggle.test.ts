import { describe, it, expect, beforeEach } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import {
  useThemeToggle,
  readSavedTheme,
  readEffectiveBootTheme,
  THEME_STORAGE_KEY,
  LAB_THEME_STORAGE_KEY,
} from '../useThemeToggle';

describe('useThemeToggle', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    delete document.documentElement.dataset.theme;
  });

  it('readSavedTheme defaults to dark', () => {
    expect(readSavedTheme()).toBe('dark');
  });

  it('readSavedTheme returns light when saved', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'light');
    expect(readSavedTheme()).toBe('light');
  });

  it('readSavedTheme rejects junk values', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'banana');
    expect(readSavedTheme()).toBe('dark');
  });

  it('readEffectiveBootTheme prefers sessionStorage lab over localStorage', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'dark');
    sessionStorage.setItem(LAB_THEME_STORAGE_KEY, 'light');
    expect(readEffectiveBootTheme()).toBe('light');
  });

  it('readEffectiveBootTheme falls back to localStorage when no lab override', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'light');
    expect(readEffectiveBootTheme()).toBe('light');
  });

  it('toggle flips theme, writes localStorage, sets data-theme', () => {
    const { result } = renderHook(() => useThemeToggle());
    expect(result.current.theme).toBe('dark');

    act(() => result.current.toggle({ clientX: 100, clientY: 50 }));
    expect(result.current.theme).toBe('light');
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');
    expect(document.documentElement.dataset.theme).toBe('light');

    act(() => result.current.toggle({ clientX: 100, clientY: 50 }));
    expect(result.current.theme).toBe('dark');
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark');
    expect(document.documentElement.dataset.theme).toBe('dark');
  });

  it('toggle without click coords still flips theme', () => {
    const { result } = renderHook(() => useThemeToggle());
    act(() => result.current.toggle());
    expect(result.current.theme).toBe('light');
    expect(document.documentElement.dataset.theme).toBe('light');
  });

  it('hydrates from data-theme attribute set pre-mount by App.tsx', () => {
    document.documentElement.dataset.theme = 'light';
    localStorage.setItem(THEME_STORAGE_KEY, 'light');
    const { result } = renderHook(() => useThemeToggle());
    expect(result.current.theme).toBe('light');
  });
});
