/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { useFullscreenMode } from './useFullscreenMode';

beforeEach(() => {
  document.body.classList.remove('maze-fullscreen');
});

describe('useFullscreenMode', () => {
  it('starts off and toggles cleanly', () => {
    const { result } = renderHook(() => useFullscreenMode());
    expect(result.current.fullscreen).toBe(false);
    act(() => result.current.toggle());
    expect(result.current.fullscreen).toBe(true);
    act(() => result.current.toggle());
    expect(result.current.fullscreen).toBe(false);
  });

  it('adds the maze-fullscreen body class only while active', () => {
    const { result } = renderHook(() => useFullscreenMode());
    expect(document.body.classList.contains('maze-fullscreen')).toBe(false);
    act(() => result.current.setFullscreen(true));
    expect(document.body.classList.contains('maze-fullscreen')).toBe(true);
    act(() => result.current.setFullscreen(false));
    expect(document.body.classList.contains('maze-fullscreen')).toBe(false);
  });

  it('Esc keystroke flips fullscreen back off', () => {
    const { result } = renderHook(() => useFullscreenMode());
    act(() => result.current.setFullscreen(true));
    expect(result.current.fullscreen).toBe(true);
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    });
    expect(result.current.fullscreen).toBe(false);
  });

  it('clears the body class on unmount', () => {
    const { result, unmount } = renderHook(() => useFullscreenMode());
    act(() => result.current.setFullscreen(true));
    expect(document.body.classList.contains('maze-fullscreen')).toBe(true);
    unmount();
    expect(document.body.classList.contains('maze-fullscreen')).toBe(false);
  });
});
