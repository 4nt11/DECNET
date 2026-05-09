import React from 'react';
import {
  Cpu, Database, Globe, Monitor, Server, Shield, Terminal,
} from '../../icons';
import type { Decky, DeckyStatus } from './types';

/** Map an archetype slug to a lucide icon name used by PickIcon. */
export const archetypeIcon = (slug: string): string => {
  const s = slug.toLowerCase();
  if (s.includes('windows') || s.includes('workstation')) return 'monitor';
  if (s.includes('domain')) return 'shield';
  if (s.includes('database') || s.includes('sql')) return 'database';
  if (s.includes('iot') || s.includes('ot')) return 'cpu';
  if (s.includes('web')) return 'globe';
  return 'server';
};

/** Compact icon resolver for the lucide names DeckyFleet/DeployWizard
 *  reference by string (data-driven archetype rows). Unknown names
 *  fall back to the server icon. */
export const PickIcon: React.FC<{ name: string; size?: number; className?: string }> = (
  { name, size = 16, className },
) => {
  const map: Record<string, React.ComponentType<{ size?: number; className?: string }>> = {
    server: Server, monitor: Monitor, shield: Shield, database: Database,
    cpu: Cpu, globe: Globe, terminal: Terminal,
  };
  const Cmp = map[name] ?? Server;
  return <Cmp size={size} className={className} />;
};

/** Map swarm state -> visual dot status. "active" with no recent hit
 *  is idle; we don't have per-decky hit counts here, so treat
 *  running = active. */
export const dotFor = (d: Decky): DeckyStatus => {
  if (!d.swarm) return 'active';
  switch (d.swarm.state) {
    case 'running': return 'active';
    case 'failed':
    case 'teardown_failed': return 'hot';
    case 'pending':
    case 'tearing_down':
    case 'degraded': return 'idle';
    default: return 'idle';
  }
};

/** Hits placeholder — backend doesn't expose per-decky 24h hit count yet. */
export const hitsFor = (_d: Decky): number => 0;

/** CSS variable name for a swarm-state dot color. */
export const stateColor = (state: string): string => {
  switch (state) {
    case 'running': return 'var(--matrix)';
    case 'degraded':
    case 'tearing_down':
    case 'pending': return 'var(--violet)';
    case 'failed':
    case 'teardown_failed': return 'var(--alert)';
    default: return 'var(--border)';
  }
};
