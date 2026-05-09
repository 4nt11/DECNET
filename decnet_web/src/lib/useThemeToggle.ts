import { useCallback, useEffect, useState } from 'react';

/* User-facing dark/light theme management.
 *
 * Two persistence layers:
 *   - localStorage `decnet_theme`  — the user's saved preference.
 *     Survives reloads, applies to every tab.
 *   - sessionStorage `decnet_theme_lab` — dev-mode lab override
 *     (set from /theme-lab). Tab-scoped, wins over localStorage on
 *     boot so devs can A/B without nuking their saved preference.
 *
 * Both write the same `data-theme` attribute on <html>. The toggle
 * called from the topbar updates localStorage; the lab toggle
 * (Task 3) updates sessionStorage. App.tsx hydrates on boot.
 *
 * Animation: when supported, the swap rides the View Transitions
 * API with a circle clip-path that grows from the click point to
 * cover the viewport diagonal. Browsers without the API still get
 * the theme swap, just without the reveal. */

export const THEME_STORAGE_KEY = 'decnet_theme';
export const LAB_THEME_STORAGE_KEY = 'decnet_theme_lab';

export type Theme = 'dark' | 'light';

function isTheme(v: unknown): v is Theme {
  return v === 'dark' || v === 'light';
}

export function readSavedTheme(): Theme {
  try {
    const v = localStorage.getItem(THEME_STORAGE_KEY);
    return isTheme(v) ? v : 'dark';
  } catch {
    return 'dark';
  }
}

export function readEffectiveBootTheme(): Theme {
  // sessionStorage (lab) wins over localStorage on boot.
  try {
    const lab = sessionStorage.getItem(LAB_THEME_STORAGE_KEY);
    if (isTheme(lab)) return lab;
  } catch { /* ignore */ }
  return readSavedTheme();
}

interface ViewTransitionDoc {
  startViewTransition?: (cb: () => void | Promise<void>) => {
    ready: Promise<void>;
    finished: Promise<void>;
  };
}

/* Animate the theme swap with a circle clip-path that grows from
 * (x, y) to the farthest viewport corner. Falls back to an
 * unanimated swap when View Transitions aren't available. */
function animateSwap(next: Theme, x: number, y: number): void {
  const docVT = document as unknown as ViewTransitionDoc;
  const apply = () => { document.documentElement.dataset.theme = next; };

  if (typeof docVT.startViewTransition !== 'function') {
    apply();
    return;
  }

  /* Publish click coords as CSS custom properties BEFORE the
   * transition starts — index.css uses these in the
   * ::view-transition-new(root) default rule so the new pseudo
   * is already clipped to circle(0) at this point on its first
   * paint. Without this, the new layer renders at default styles
   * (full size) for one frame before the animation registers. */
  document.documentElement.style.setProperty('--reveal-x', `${x}px`);
  document.documentElement.style.setProperty('--reveal-y', `${y}px`);

  const transition = docVT.startViewTransition(apply)!;
  transition.ready.then(() => {
    const endRadius = Math.hypot(
      Math.max(x, window.innerWidth - x),
      Math.max(y, window.innerHeight - y),
    );
    /* Grow the NEW layer (on top per index.css z-index rules)
     * outward from the click point, covering the OLD layer that
     * sits behind. fill: 'both' pins both ends of the keyframe
     * range so the start state (clipped to a 0-radius circle)
     * is enforced before the first paint and the end state
     * (full-viewport circle) holds through pseudo teardown —
     * killing the flash on either end of the animation. */
    document.documentElement.animate(
      {
        clipPath: [
          `circle(0px at ${x}px ${y}px)`,
          `circle(${endRadius}px at ${x}px ${y}px)`,
        ],
      },
      {
        duration: 520,
        easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
        pseudoElement: '::view-transition-new(root)',
        fill: 'both',
      },
    );
  }).catch(() => { /* user-cancelled or unsupported pseudo, ignore */ });
}

export function useThemeToggle() {
  const [theme, setTheme] = useState<Theme>(() => readSavedTheme());

  /* Keep React state aligned with whatever boot-time hydration set
   * on <html>, in case App.tsx already wrote the attribute. */
  useEffect(() => {
    const fromAttr = document.documentElement.dataset.theme;
    if (isTheme(fromAttr) && fromAttr !== theme) {
      setTheme(fromAttr);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const toggle = useCallback((e?: { clientX?: number; clientY?: number }) => {
    const next: Theme = theme === 'dark' ? 'light' : 'dark';
    const x = e?.clientX ?? window.innerWidth - 32;
    const y = e?.clientY ?? 32;
    try { localStorage.setItem(THEME_STORAGE_KEY, next); } catch { /* ignore */ }
    animateSwap(next, x, y);
    setTheme(next);
  }, [theme]);

  return { theme, toggle };
}
