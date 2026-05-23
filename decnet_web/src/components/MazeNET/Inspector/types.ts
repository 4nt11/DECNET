// SPDX-License-Identifier: AGPL-3.0-or-later
export type Selection =
  | { type: 'net'; id: string }
  | { type: 'node'; id: string }
  | { type: 'edge'; id: string }
  | { type: 'service'; id: string; nodeId: string }
  | null;
