import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

interface Options {
  cmdOpen: boolean;
  setCmdOpen: (v: boolean | ((prev: boolean) => boolean)) => void;
  helpOpen: boolean;
  setHelpOpen: (v: boolean | ((prev: boolean) => boolean)) => void;
}

const G_NAV: Record<string, string> = {
  d: '/',
  f: '/fleet',
  m: '/mazenet',
  l: '/live-logs',
  b: '/bounty',
  a: '/attackers',
  c: '/config',
  s: '/swarm/hosts',
  u: '/swarm-updates',
  e: '/swarm/enroll',
};

const G_TIMEOUT_MS = 800;

function isEditable(el: EventTarget | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  const tag = el.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || el.isContentEditable;
}

export function useGlobalHotkeys({ cmdOpen, setCmdOpen, helpOpen, setHelpOpen }: Options): void {
  const navigate = useNavigate();
  const pendingG = useRef(false);
  const gTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const clearG = () => {
      pendingG.current = false;
      if (gTimer.current) { clearTimeout(gTimer.current); gTimer.current = null; }
    };

    const onKey = (e: KeyboardEvent) => {
      if (e.altKey && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCmdOpen(v => !v);
        clearG();
        return;
      }

      if (e.key === 'Escape' && cmdOpen) {
        setCmdOpen(false);
        clearG();
        return;
      }

      if (cmdOpen || helpOpen) return;
      if (isEditable(e.target)) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      // `?` (Shift+/) — open shortcuts cheatsheet
      if (e.key === '?') {
        e.preventDefault();
        setHelpOpen(true);
        clearG();
        return;
      }

      // `/` — focus page search (page listens for the event)
      if (e.key === '/') {
        e.preventDefault();
        window.dispatchEvent(new CustomEvent('decnet:focus-search'));
        clearG();
        return;
      }

      const k = e.key.toLowerCase();

      if (pendingG.current && G_NAV[k]) {
        e.preventDefault();
        navigate(G_NAV[k]);
        clearG();
        return;
      }

      if (k === 'g') {
        pendingG.current = true;
        if (gTimer.current) clearTimeout(gTimer.current);
        gTimer.current = setTimeout(clearG, G_TIMEOUT_MS);
      }
    };

    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      if (gTimer.current) clearTimeout(gTimer.current);
    };
  }, [cmdOpen, setCmdOpen, helpOpen, setHelpOpen, navigate]);
}
