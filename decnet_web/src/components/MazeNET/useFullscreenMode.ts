import { useEffect, useState } from 'react';

const BODY_CLASS = 'maze-fullscreen';

export interface UseFullscreenModeResult {
  fullscreen: boolean;
  setFullscreen: (next: boolean | ((prev: boolean) => boolean)) => void;
  toggle: () => void;
}

/** Fullscreen-mode state for the MazeNET canvas. Owns four
 *  side-effects:
 *    1. Toggle a body class so the page CSS can hide its chrome.
 *    2. Request/exit the browser-level fullscreen API (failures
 *       are ignored; chrome-only mode still works without it).
 *    3. Listen for fullscreenchange so F11/Esc from outside our
 *       button keeps internal state in sync.
 *    4. Esc shortcut to leave fullscreen via keyboard. */
export function useFullscreenMode(): UseFullscreenModeResult {
  const [fullscreen, setFullscreen] = useState(false);

  useEffect(() => {
    if (fullscreen) document.body.classList.add(BODY_CLASS);
    else document.body.classList.remove(BODY_CLASS);
    return () => document.body.classList.remove(BODY_CLASS);
  }, [fullscreen]);

  // Request/exit browser fullscreen alongside the in-app chrome hide.
  // Ignore failures (fullscreen requires a user gesture; the chrome-only
  // mode still works if the API rejects).
  useEffect(() => {
    if (fullscreen && !document.fullscreenElement) {
      document.documentElement.requestFullscreen?.().catch(() => {});
    } else if (!fullscreen && document.fullscreenElement) {
      document.exitFullscreen?.().catch(() => {});
    }
  }, [fullscreen]);

  // Sync state if the user presses F11/Esc to leave fullscreen from
  // outside our button.
  useEffect(() => {
    const onFsChange = () => {
      if (!document.fullscreenElement) setFullscreen(false);
    };
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && fullscreen) setFullscreen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [fullscreen]);

  return {
    fullscreen,
    setFullscreen,
    toggle: () => setFullscreen((f) => !f),
  };
}
