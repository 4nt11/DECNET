// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect } from 'react';
import type { RefObject } from 'react';

/**
 * Focus the given input when the global `decnet:focus-search` event fires
 * (dispatched by the `/` hotkey in useGlobalHotkeys).
 */
export function useFocusSearch(ref: RefObject<HTMLInputElement | null>): void {
  useEffect(() => {
    const handler = () => {
      const el = ref.current;
      if (!el) return;
      el.focus();
      try { el.select(); } catch { /* ignore */ }
    };
    window.addEventListener('decnet:focus-search', handler);
    return () => window.removeEventListener('decnet:focus-search', handler);
  }, [ref]);
}
