export type Selection =
  | { type: 'net'; id: string }
  | { type: 'node'; id: string }
  | { type: 'edge'; id: string }
  | { type: 'service'; id: string; nodeId: string }
  | null;
