export type NetKind = 'internet' | 'subnet' | 'dmz';

export interface Net {
  id: string;
  label: string;
  cidr: string;
  kind: NetKind;
  x: number;
  y: number;
  w: number;
  h: number;
}

export type NodeKind = 'decky' | 'observed';

interface NodeBase {
  id: string;
  netId: string;
  name: string;
  archetype: string;
  services: string[];
  status: 'active' | 'idle' | 'hot' | 'mutating';
  x: number;
  y: number;
}

export interface DeckyNode extends NodeBase {
  kind: 'decky';
  ip?: string;
  decky_config?: Record<string, unknown>;
  mutate_interval?: number | null;
}

export interface ObservedNode extends NodeBase {
  kind: 'observed';
  archetype: 'attacker-pool';
  services: ['*'];
}

export type MazeNode = DeckyNode | ObservedNode;

export interface Edge {
  id: string;
  from: string;
  to: string;
  traffic: 'hot' | 'active' | 'idle';
  label?: string;
}

