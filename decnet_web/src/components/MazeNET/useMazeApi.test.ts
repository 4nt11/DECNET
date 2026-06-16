// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { adaptTopology } from './useMazeApi';

/** Reproduces the live topology from the field report:
 *  dmz + subnet-B + subnet-C, a DMZ-homed L3 gateway bridged into B,
 *  and decky-7371 (home C) bridged into B to "link C to B". The bug was
 *  a phantom C->root edge, because the gateway is displayed in the DMZ
 *  but co-resides in B. */
const detail = {
  topology: { id: 't', name: 'test', mode: 'unihost', target_host_uuid: null, status: 'active', version: 3 },
  lans: [
    { id: 'dmz', topology_id: 't', name: 'dmz', subnet: '10.0.0.0/24', is_dmz: true },
    { id: 'B', topology_id: 't', name: 'subnet-b', subnet: '10.0.1.0/24', is_dmz: false },
    { id: 'C', topology_id: 't', name: 'subnet-c', subnet: '10.0.2.0/24', is_dmz: false },
  ],
  deckies: [
    { uuid: 'gw', topology_id: 't', name: 'dmz-gateway', services: [], decky_config: { forwards_l3: true }, state: 'running' },
    { uuid: 'd5201', topology_id: 't', name: 'decky-5201', services: [], decky_config: {}, state: 'running' },
    { uuid: 'd7371', topology_id: 't', name: 'decky-7371', services: [], decky_config: {}, state: 'running' },
  ],
  edges: [
    { id: 'e1', topology_id: 't', decky_uuid: 'gw', lan_id: 'dmz', is_bridge: true, forwards_l3: true },
    { id: 'e2', topology_id: 't', decky_uuid: 'gw', lan_id: 'B', is_bridge: true, forwards_l3: false },
    { id: 'e3', topology_id: 't', decky_uuid: 'd5201', lan_id: 'B', is_bridge: false, forwards_l3: false },
    { id: 'e4', topology_id: 't', decky_uuid: 'd7371', lan_id: 'C', is_bridge: false, forwards_l3: false },
    { id: 'e5', topology_id: 't', decky_uuid: 'd7371', lan_id: 'B', is_bridge: true, forwards_l3: false },
  ],
};

const hasEdge = (edges: { from: string; to: string }[], a: string, b: string) =>
  edges.some((e) => (e.from === a && e.to === b) || (e.from === b && e.to === a));

describe('adaptTopology edge derivation', () => {
  it('drops the phantom visitor↔visitor edge but keeps real connections', () => {
    const { edges } = adaptTopology(detail as never);

    // Phantom: decky-7371 (home C) ↔ gateway (home DMZ), both merely
    // visiting B — would render C->root. Must be suppressed.
    expect(hasEdge(edges, 'd7371', 'gw')).toBe(false);

    // Real link: decky-7371 (home C) ↔ decky-5201 (home B) — C reaches B.
    expect(hasEdge(edges, 'd7371', 'd5201')).toBe(true);

    // Real link preserved: decky-5201 (home B) ↔ gateway — B reaches root.
    expect(hasEdge(edges, 'd5201', 'gw')).toBe(true);
  });

  it('honours backend x/y when present, grids otherwise', () => {
    const d = {
      topology: { id: 't', name: 't', mode: 'unihost', target_host_uuid: null, status: 'active', version: 1 },
      lans: [
        { id: 'L1', topology_id: 't', name: 'placed', subnet: '10.0.0.0/24', is_dmz: true, x: 512, y: 384 },
        { id: 'L2', topology_id: 't', name: 'gridded', subnet: '10.0.1.0/24', is_dmz: false, x: null, y: null },
      ],
      deckies: [
        { uuid: 'p', topology_id: 't', name: 'placed-d', services: [], decky_config: {}, state: 'running', x: 200, y: 150 },
      ],
      edges: [
        { id: 'e', topology_id: 't', decky_uuid: 'p', lan_id: 'L1', is_bridge: false, forwards_l3: false },
      ],
    };
    const { nets, nodes } = adaptTopology(d as never);
    const placed = nets.find((n) => n.id === 'L1')!;
    const gridded = nets.find((n) => n.id === 'L2')!;
    expect([placed.x, placed.y]).toEqual([512, 384]); // stored coords kept
    // null → grid; L2 is index 1 in the dmz-first order → second column.
    expect([gridded.x, gridded.y]).toEqual([380, 40]);
    expect([nodes[0].x, nodes[0].y]).toEqual([200, 150]);
  });
});
