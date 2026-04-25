export type NetKind = 'internet' | 'subnet' | 'dmz';

export interface Net {
  id: string;
  /** Display string (uppercased for the canvas chrome). */
  label: string;
  /** Canonical LAN name as stored on the backend — lowercase. Use
   *  this (not ``label``) for any API call that identifies a LAN by
   *  name (mutator attach/detach, delete, etc.); the mutator looks
   *  up case-sensitively and will 404 on the uppercased form. */
  name: string;
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
  /** Backend membership-edge id when this visual edge mirrors a
   *  cross-LAN bridge attachment. Same-LAN edges stay visual-only
   *  and leave this undefined. Set at attach, consumed at detach. */
  backendEdgeId?: string;
}

