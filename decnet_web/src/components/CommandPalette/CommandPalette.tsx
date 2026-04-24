import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  LayoutDashboard, Server, Network, Terminal, Archive, Crosshair,
  PlusCircle, Pause, RefreshCw, Download, HardDrive, Package, Settings,
  SearchX, Keyboard, Webhook,
} from 'lucide-react';
import EmptyState from '../EmptyState/EmptyState';
import './CommandPalette.css';

type IconComponent = React.ComponentType<{ size?: number; className?: string }>;

interface CmdItem {
  section: 'GO TO' | 'ACTIONS';
  label: string;
  icon: IconComponent;
  kbd?: string;
  kind: 'nav' | 'action';
  payload: string;
}

const ITEMS: CmdItem[] = [
  { section: 'GO TO', label: 'Dashboard',    icon: LayoutDashboard, kbd: 'G D', kind: 'nav', payload: '/' },
  { section: 'GO TO', label: 'Decoy Fleet',  icon: Server,          kbd: 'G F', kind: 'nav', payload: '/fleet' },
  { section: 'GO TO', label: 'MazeNET',      icon: Network,         kbd: 'G M', kind: 'nav', payload: '/mazenet' },
  { section: 'GO TO', label: 'Live Logs',    icon: Terminal,        kbd: 'G L', kind: 'nav', payload: '/live-logs' },
  { section: 'GO TO', label: 'Webhooks',     icon: Webhook,         kbd: 'G W', kind: 'nav', payload: '/webhooks' },
  { section: 'GO TO', label: 'Bounty Vault', icon: Archive,         kbd: 'G B', kind: 'nav', payload: '/bounty' },
  { section: 'GO TO', label: 'Attackers',    icon: Crosshair,       kbd: 'G A', kind: 'nav', payload: '/attackers' },
  { section: 'GO TO', label: 'SWARM Hosts',     icon: HardDrive, kbd: 'G S', kind: 'nav', payload: '/swarm/hosts' },
  { section: 'GO TO', label: 'Remote Updates',  icon: Package,   kbd: 'G U', kind: 'nav', payload: '/swarm-updates' },
  { section: 'GO TO', label: 'Config',          icon: Settings,  kbd: 'G C', kind: 'nav', payload: '/config' },
  { section: 'ACTIONS', label: 'Deploy new decky',        icon: PlusCircle, kind: 'action', payload: 'deploy' },
  { section: 'ACTIONS', label: 'Pause live stream',       icon: Pause,      kind: 'action', payload: 'pause-logs' },
  { section: 'ACTIONS', label: 'Force mutate all deckies', icon: RefreshCw, kind: 'action', payload: 'mutate-all' },
  { section: 'ACTIONS', label: 'Export bounty to JSON',   icon: Download,   kind: 'action', payload: 'export-bounty' },
  { section: 'ACTIONS', label: 'Show keyboard shortcuts', icon: Keyboard,   kbd: '?', kind: 'action', payload: 'shortcuts-help' },
];

interface Props {
  open: boolean;
  onClose: () => void;
  onNav: (path: string) => void;
  onAction: (id: string) => void;
}

const CommandPalette: React.FC<Props> = ({ open, onClose, onNav, onAction }) => {
  const [query, setQuery] = useState('');
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return ITEMS;
    return ITEMS.filter(it =>
      it.label.toLowerCase().includes(q) || it.section.toLowerCase().includes(q)
    );
  }, [query]);

  useEffect(() => {
    if (open) {
      setQuery('');
      setSel(0);
      const t = setTimeout(() => inputRef.current?.focus(), 30);
      return () => clearTimeout(t);
    }
  }, [open]);

  useEffect(() => { setSel(0); }, [query]);

  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-cmd-idx="${sel}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }, [sel]);

  if (!open) return null;

  const fire = (it: CmdItem) => {
    if (it.kind === 'nav') onNav(it.payload);
    else onAction(it.payload);
    onClose();
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') { onClose(); return; }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSel(s => (filtered.length ? (s + 1) % filtered.length : 0));
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSel(s => (filtered.length ? (s - 1 + filtered.length) % filtered.length : 0));
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      const it = filtered[sel];
      if (it) fire(it);
    }
  };

  const groups = filtered.reduce<Record<string, CmdItem[]>>((acc, it) => {
    (acc[it.section] ||= []).push(it);
    return acc;
  }, {});

  let idx = -1;

  return (
    <div className="cmd-backdrop" onClick={onClose}>
      <div className="cmd-palette" onClick={e => e.stopPropagation()}>
        <div className="cmd-input-wrap">
          <Terminal size={16} className="violet-accent" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKey}
            placeholder="Type a command or search…"
          />
          <span className="search-kbd">ESC</span>
        </div>
        <div className="cmd-list" ref={listRef}>
          {Object.entries(groups).map(([section, items]) => (
            <div key={section}>
              <div className="cmd-group-label">{section}</div>
              {items.map(it => {
                idx++;
                const active = idx === sel;
                const Icon = it.icon;
                return (
                  <div
                    key={it.label}
                    data-cmd-idx={idx}
                    className={`cmd-item ${active ? 'active' : ''}`}
                    onClick={() => fire(it)}
                    onMouseEnter={() => setSel(filtered.indexOf(it))}
                  >
                    <Icon size={14} className="cmd-item-icon" />
                    <span>{it.label}</span>
                    {it.kbd && <span className="cmd-kbd">{it.kbd}</span>}
                  </div>
                );
              })}
            </div>
          ))}
          {filtered.length === 0 && (
            <EmptyState icon={SearchX} title="NO COMMAND MATCHES" size="compact" />
          )}
        </div>
        <div className="cmd-hint">
          <span>↑↓ NAVIGATE · ⏎ SELECT</span>
          <span>DECNET CLI</span>
        </div>
      </div>
    </div>
  );
};

export default CommandPalette;
