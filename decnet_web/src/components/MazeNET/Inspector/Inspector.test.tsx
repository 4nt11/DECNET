// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import Inspector from './index';
import type { DeckyNode, Edge, Net, ObservedNode } from '../types';

const subnet: Net = {
  id: 'lan-1', name: 'lan-corp', label: 'CORP',
  cidr: '10.0.0.0/24', kind: 'subnet', x: 0, y: 0, w: 300, h: 240,
};
const internet: Net = {
  id: 'lan-www', name: 'internet', label: 'INTERNET',
  cidr: '0.0.0.0/0', kind: 'internet', x: 0, y: 0, w: 300, h: 240,
};
const decky: DeckyNode = {
  kind: 'decky', id: 'd1', name: 'decoy-01', netId: 'lan-1',
  archetype: 'workstation', services: ['ssh'], status: 'idle', x: 0, y: 0,
};
const observed: ObservedNode = {
  kind: 'observed', id: 'obs-1', netId: 'lan-www', name: '1.2.3.4',
  archetype: 'attacker-pool', services: ['*'], status: 'idle', x: 0, y: 0,
};
const edge: Edge = {
  id: 'e-1', from: 'obs-1', to: 'd1', traffic: 'hot',
};

describe('Inspector dispatcher', () => {
  it('shows the empty state when nothing is selected', () => {
    render(
      <Inspector selection={null} nets={[subnet]} nodes={[decky]} edges={[]} />,
    );
    expect(screen.getByText(/SELECT A NODE/)).toBeInTheDocument();
  });

  it('renders NodeInspector when a node is selected', () => {
    render(
      <Inspector
        selection={{ type: 'node', id: 'd1' }}
        nets={[subnet]} nodes={[decky]} edges={[]}
      />,
    );
    expect(screen.getByText('decoy-01')).toBeInTheDocument();
    expect(screen.getByText('workstation')).toBeInTheDocument();
    expect(screen.getByText('CONNECTIONS')).toBeInTheDocument();
  });

  it('renders NetInspector when a net is selected and shows the INACTIVE chip', () => {
    render(
      <Inspector
        selection={{ type: 'net', id: 'lan-1' }}
        nets={[subnet]} nodes={[decky]} edges={[]}
      />,
    );
    expect(screen.getByText('CORP')).toBeInTheDocument();
    expect(screen.getByText('INACTIVE')).toBeInTheDocument();
  });

  it('renders EdgeInspector and fires onDeleteEdge', () => {
    const onDeleteEdge = vi.fn();
    render(
      <Inspector
        selection={{ type: 'edge', id: 'e-1' }}
        nets={[subnet, internet]} nodes={[decky, observed]} edges={[edge]}
        onDeleteEdge={onDeleteEdge}
      />,
    );
    expect(screen.getByText(/EDGE ·/)).toBeInTheDocument();
    fireEvent.click(screen.getByText(/CUT EDGE/));
    expect(onDeleteEdge).toHaveBeenCalledWith('e-1');
  });

  it('renders ServiceInspector with the parent decky and remove button', () => {
    const onRemoveService = vi.fn();
    render(
      <Inspector
        selection={{ type: 'service', id: 'ssh', nodeId: 'd1' }}
        nets={[subnet]} nodes={[decky]} edges={[]}
        onRemoveService={onRemoveService}
      />,
    );
    expect(screen.getByText('decoy-01')).toBeInTheDocument();
    fireEvent.click(screen.getByText(/REMOVE SERVICE/));
    expect(onRemoveService).toHaveBeenCalledWith('d1', 'ssh');
  });

  it('forbids deleting an observed entity in NodeInspector', () => {
    const onDeleteNode = vi.fn();
    render(
      <Inspector
        selection={{ type: 'node', id: 'obs-1' }}
        nets={[internet]} nodes={[observed]} edges={[]}
        onDeleteNode={onDeleteNode}
      />,
    );
    const btn = screen.getByText(/REMOVE FROM GRAPH/).closest('button')!;
    expect(btn).toBeDisabled();
  });

  it('forbids deleting the internet net', () => {
    render(
      <Inspector
        selection={{ type: 'net', id: 'lan-www' }}
        nets={[internet]} nodes={[observed]} edges={[]}
        onDeleteNet={() => {}}
      />,
    );
    expect(screen.queryByText(/REMOVE NETWORK/)).toBeNull();
  });

  it('hides live-ops controls on a pending topology', () => {
    render(
      <Inspector
        selection={{ type: 'node', id: 'd1' }}
        nets={[subnet]} nodes={[decky]} edges={[]}
        topologyStatus="pending"
        onLiveAddService={vi.fn()}
        onLiveRemoveService={vi.fn()}
        onLiveTarpitEnable={vi.fn()}
        onLiveTarpitDisable={vi.fn()}
      />,
    );
    expect(screen.queryByText(/TARPIT/)).toBeNull();
    expect(screen.queryByText(/ ADD$/)).toBeNull();
  });

  it('shows tarpit controls when topologyStatus=active and the callbacks are present', () => {
    render(
      <Inspector
        selection={{ type: 'node', id: 'd1' }}
        nets={[subnet]} nodes={[decky]} edges={[]}
        topologyStatus="active"
        onLiveAddService={vi.fn()}
        onLiveRemoveService={vi.fn()}
        onLiveTarpitEnable={vi.fn()}
        onLiveTarpitDisable={vi.fn()}
      />,
    );
    expect(screen.getByText('TARPIT')).toBeInTheDocument();
    expect(screen.getByText('DISABLE')).toBeInTheDocument();
  });

  it('renders pending-diff block when pendingChanges > 0', () => {
    render(
      <Inspector
        selection={null}
        nets={[subnet]} nodes={[decky]} edges={[]}
        pendingChanges={3}
      />,
    );
    expect(screen.getByText('PENDING DIFF')).toBeInTheDocument();
    expect(screen.getByText(/\+3 graph mutation/)).toBeInTheDocument();
  });
});
