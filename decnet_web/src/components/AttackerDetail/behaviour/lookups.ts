// SPDX-License-Identifier: AGPL-3.0-or-later
import type React from 'react';
import {
  Activity, Clock, Cpu, Globe, Keyboard, Sparkles,
} from '../../../icons';
import type { AttributionPrimitiveState } from '../types';

export const OS_LABELS: Record<string, string> = {
  linux: 'LINUX',
  windows: 'WINDOWS',
  macos_ios: 'macOS / iOS',
  freebsd: 'FREEBSD',
  openbsd: 'OPENBSD',
  embedded: 'EMBEDDED',
  nmap: 'NMAP (SCANNER)',
  unknown: 'UNKNOWN',
};

export const BEHAVIOR_LABELS: Record<string, string> = {
  beaconing:   'BEACONING',
  interactive: 'INTERACTIVE',
  scanning:    'SCANNING',
  brute_force: 'BRUTE FORCE',
  slow_scan:   'SLOW SCAN',
  mixed:       'MIXED',
  unknown:     'UNKNOWN',
};

export const BEHAVIOR_COLORS: Record<string, string> = {
  beaconing:   '#ff6b6b',
  interactive: 'var(--accent-color)',
  scanning:    '#e5c07b',
  brute_force: '#ff9f43',
  slow_scan:   '#c8a96e',
  mixed:       'var(--text-color)',
  unknown:     'var(--text-color)',
};

export const TOOL_LABELS: Record<string, string> = {
  cobalt_strike: 'COBALT STRIKE',
  sliver: 'SLIVER',
  havoc: 'HAVOC',
  mythic: 'MYTHIC',
  nmap: 'NMAP',
  gophish: 'GOPHISH',
  nikto: 'NIKTO',
  sqlmap: 'SQLMAP',
  nuclei: 'NUCLEI',
  masscan: 'MASSCAN',
  zgrab: 'ZGRAB',
  metasploit: 'METASPLOIT',
  gobuster: 'GOBUSTER',
  dirbuster: 'DIRBUSTER',
  hydra: 'HYDRA',
  wfuzz: 'WFUZZ',
  curl: 'CURL',
  python_requests: 'PYTHON-REQUESTS',
};

// Tools detected via beacon timing (C2 frameworks).
export const C2_TOOLS = new Set(['cobalt_strike', 'sliver', 'havoc', 'mythic']);

export const fmtOpt = (v: number | null | undefined): string =>
  v === null || v === undefined ? '—' : String(v);

export const fmtSecs = (v: number | null | undefined): string => {
  if (v === null || v === undefined) return '—';
  if (v < 1) return `${(v * 1000).toFixed(0)} ms`;
  if (v < 60) return `${v.toFixed(2)} s`;
  if (v < 3600) return `${(v / 60).toFixed(2)} m`;
  return `${(v / 3600).toFixed(2)} h`;
};

// ─── Behavioural primitives panel (BEHAVE-INTEGRATION Phase 5) ─────────────

// Day-one render priority per BEHAVE-INTEGRATION.md §441-454. These four
// primitives carry the highest discriminative value for the "is this the
// same operator class" hover story; everything else alphabetises.
export const BEHAVIOUR_PRIORITY: ReadonlyArray<string> = [
  'motor.input_modality',
  'cognitive.feedback_loop_engagement',
  'cognitive.command_branch_diversity',
  'cognitive.inter_command_latency_class',
];

export const BEHAVIOUR_DOMAIN_ORDER: ReadonlyArray<string> = [
  'motor', 'cognitive', 'temporal', 'operational',
  'environmental', 'emotional_valence',
];

export const BEHAVIOUR_DOMAIN_LABELS: Record<string, string> = {
  motor: 'MOTOR',
  cognitive: 'COGNITIVE',
  temporal: 'TEMPORAL',
  operational: 'OPERATIONAL',
  environmental: 'ENVIRONMENTAL',
  emotional_valence: 'EMOTIONAL VALENCE',
};

export const BEHAVIOUR_DOMAIN_ICONS: Record<string, React.ComponentType<{ size?: number; style?: React.CSSProperties }>> = {
  motor: Keyboard,
  cognitive: Cpu,
  temporal: Clock,
  operational: Activity,
  environmental: Globe,
  emotional_valence: Sparkles,
};

export function domainOf(primitive: string): string {
  return primitive.split('.', 1)[0];
}

export function leafOf(primitive: string): string {
  return primitive.split('.').slice(1).join('.');
}

export function comparePrimitives(a: string, b: string): number {
  const ai = BEHAVIOUR_PRIORITY.indexOf(a);
  const bi = BEHAVIOUR_PRIORITY.indexOf(b);
  if (ai !== -1 && bi !== -1) return ai - bi;
  if (ai !== -1) return -1;
  if (bi !== -1) return 1;
  return a.localeCompare(b);
}

export function renderValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

// Per-state badge styling. Five states, frozen vocabulary —
// matches decnet/correlation/attribution/aggregate.py. multi_actor is
// the loudest because the cross-primitive correlator (Phase 5) only
// fires multi_actor_suspected when >= 2 primitives flag it.
export const ATTRIBUTION_STATE_STYLE: Record<
  AttributionPrimitiveState['state'],
  { label: string; bg: string; fg: string; border: string }
> = {
  stable:      { label: 'STABLE',      bg: 'rgba(64,224,128,0.12)',  fg: '#7fe9a4', border: '#3a8c5a' },
  drifting:    { label: 'DRIFTING',    bg: 'rgba(240,196,64,0.12)',  fg: '#f0c440', border: '#a08020' },
  conflicted:  { label: 'CONFLICTED',  bg: 'rgba(240,96,96,0.12)',   fg: '#f06060', border: '#a04040' },
  multi_actor: { label: 'MULTI-ACTOR', bg: 'rgba(180,96,240,0.16)',  fg: '#c896f6', border: '#7a4fb0' },
  unknown:     { label: 'UNKNOWN',     bg: 'transparent',            fg: 'var(--text-dim,#888)', border: 'var(--border-color)' },
};
