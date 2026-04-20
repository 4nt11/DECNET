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

/* ── Pending changes — mirrors Phase-3 MutationEnqueueRequest.op ── */
export type PendingChange =
  | { op: 'add_lan';       payload: { id: string; label: string; cidr: string; x: number; y: number; w: number; h: number } }
  | { op: 'remove_lan';    payload: { id: string } }
  | { op: 'update_lan';    payload: { id: string; patch: Partial<Net> } }
  | { op: 'attach_decky';  payload: { nodeId: string; netId: string; archetype: string; name: string; x: number; y: number; services: string[] } }
  | { op: 'detach_decky';  payload: { nodeId: string; netId: string } }
  | { op: 'remove_decky';  payload: { nodeId: string } }
  | { op: 'update_decky';  payload: { nodeId: string; patch: Partial<DeckyNode> } }
  | { op: 'add_edge';      payload: { id: string; from: string; to: string } }
  | { op: 'remove_edge';   payload: { id: string } };
